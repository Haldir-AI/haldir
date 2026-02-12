import { readFile, access, lstat, readdir } from 'node:fs/promises';
import { join, relative, resolve, isAbsolute } from 'node:path';
import { verify as ed25519Verify, base64urlDecode, hashData, safeHashCompare, parseHashString } from './crypto.js';
import { canonicalizeToBuffer } from './canonical.js';
import { encodePAE } from './pae.js';
import { checkFilesystem } from './integrity.js';
import { hasSigstoreBundle, readSigstoreBundle, verifyWithSigstore } from './sigstore.js';
import { SignatureEnvelopeSchema, AttestationSchema, IntegritySchema, PermissionsSchema } from './schemas.js';
import {
  VAULT_DIR,
  HALDIR_PAYLOAD_TYPE,
  SUPPORTED_SIGNATURE_VERSIONS,
  SUPPORTED_ATTESTATION_VERSIONS,
  SUPPORTED_INTEGRITY_VERSIONS,
} from './types.js';
import type {
  VerifyOptions,
  VerifyResult,
  VerifyError,
  VerifyWarning,
  Attestation,
  Permissions,
  TrustLevel,
  SigstoreVerifyOptions,
  SigstoreVerifyResult,
} from './types.js';
import { checkRevocationForInstall, checkRevocationForRuntime } from './revocation.js';

const REQUIRED_VAULT_FILES = ['signature.json', 'attestation.json', 'integrity.json', 'permissions.json'];
const REQUIRED_VAULT_FILES_SIGSTORE = ['sigstore-bundle.json', 'attestation.json', 'integrity.json', 'permissions.json'];

const KNOWN_CRITICAL_FIELDS: string[] = [];

function normalizePath(p: string): string {
  return p.split('\\').join('/');
}

function isPathSafe(filePath: string, rootDir: string): boolean {
  const resolved = resolve(rootDir, filePath);
  const normalizedRoot = resolve(rootDir);
  const rel = relative(normalizedRoot, resolved);
  return rel.length > 0 && !rel.startsWith('..') && !isAbsolute(rel);
}

function fail(code: VerifyError['code'], message: string, file?: string): VerifyResult {
  return {
    valid: false,
    trustLevel: 'none',
    warnings: [],
    errors: [{ code, message, file }],
  };
}

async function walkFiles(dir: string, rootDir: string): Promise<string[]> {
  const results: string[] = [];
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    const rel = normalizePath(relative(rootDir, fullPath));
    if (rel.startsWith(VAULT_DIR + '/') || rel === VAULT_DIR) continue;
    if (entry.isDirectory()) {
      const sub = await walkFiles(fullPath, rootDir);
      results.push(...sub);
    } else {
      results.push(rel);
    }
  }
  return results;
}

export async function verifyEnvelope(
  skillDir: string,
  options: VerifyOptions
): Promise<VerifyResult> {
  const warnings: VerifyWarning[] = [];

  // Check 1: .vault/ exists
  const vaultDir = join(skillDir, VAULT_DIR);
  try {
    await access(vaultDir);
  } catch {
    return fail('E_NO_ENVELOPE', '.vault/ directory not found');
  }

  // Check 2: required files
  for (const f of REQUIRED_VAULT_FILES) {
    try {
      await access(join(vaultDir, f));
    } catch {
      return fail('E_INCOMPLETE', `Missing required file: ${f}`);
    }
  }

  // Check 3: symlinks
  const skipHardlink = options.context === 'runtime' && options.skipHardlinkCheck === true;
  const fsCheck = await checkFilesystem(skillDir, { skipHardlinkCheck: skipHardlink });

  const symlinkErrors = fsCheck.errors.filter((e) => e.code === 'E_SYMLINK');
  if (symlinkErrors.length > 0) {
    return { valid: false, trustLevel: 'none', warnings: [], errors: symlinkErrors };
  }

  // Check 4: hard links (skipHardlinkCheck ignored when context=install)
  const hardlinkErrors = fsCheck.errors.filter((e) => e.code === 'E_HARDLINK');
  if (hardlinkErrors.length > 0) {
    return { valid: false, trustLevel: 'none', warnings: [], errors: hardlinkErrors };
  }

  // Checks 5-7: limits
  const limitErrors = fsCheck.errors.filter((e) => e.code === 'E_LIMITS');
  if (limitErrors.length > 0) {
    return { valid: false, trustLevel: 'none', warnings: [], errors: limitErrors };
  }

  // Check 8: parse signature.json
  let signatureRaw: string;
  try {
    signatureRaw = await readFile(join(vaultDir, 'signature.json'), 'utf-8');
  } catch {
    return fail('E_INVALID_ENVELOPE', 'Could not read signature.json');
  }

  let signatureParsed: unknown;
  try {
    signatureParsed = JSON.parse(signatureRaw);
  } catch {
    return fail('E_INVALID_ENVELOPE', 'signature.json is not valid JSON');
  }

  const envelopeResult = SignatureEnvelopeSchema.safeParse(signatureParsed);
  if (!envelopeResult.success) {
    return fail('E_INVALID_ENVELOPE', `Signature envelope failed validation: ${envelopeResult.error.message}`);
  }
  const envelope = envelopeResult.data;

  // Check 9: schema version
  if (!(SUPPORTED_SIGNATURE_VERSIONS as readonly string[]).includes(envelope.schema_version)) {
    return fail('E_UNSUPPORTED_VERSION', `Unsupported signature schema version: ${envelope.schema_version}`);
  }

  // Check 10-14: signature verification (multi-sig: any match)
  // Fix #4: track decode failures separately from sig verification failures
  let verifiedKeyId: string | undefined;
  let payloadBytes: Buffer | undefined;
  let anyKeyMatched = false;
  let hadDecodeFailed = false;

  for (const sigEntry of envelope.signatures) {
    const pubKey = options.trustedKeys[sigEntry.keyid];
    if (!pubKey) continue;
    anyKeyMatched = true;

    // Check 11: decode payload
    let rawPayload: Buffer;
    try {
      rawPayload = base64urlDecode(envelope.payload);
    } catch {
      hadDecodeFailed = true;
      continue;
    }

    // Check 12: PAE
    const pae = encodePAE(envelope.payloadType, rawPayload);

    // Check 13: decode sig
    let sigBytes: Buffer;
    try {
      sigBytes = base64urlDecode(sigEntry.sig);
      if (sigBytes.length !== 64) {
        hadDecodeFailed = true;
        continue;
      }
    } catch {
      hadDecodeFailed = true;
      continue;
    }

    // Check 14: Ed25519 verify
    if (ed25519Verify(pae, sigBytes, pubKey)) {
      verifiedKeyId = sigEntry.keyid;
      payloadBytes = rawPayload;
      break;
    }
  }

  if (!anyKeyMatched) {
    return fail('E_UNKNOWN_KEY', 'No signature verified against trusted keyring');
  }
  if (!verifiedKeyId || !payloadBytes) {
    if (hadDecodeFailed) {
      return fail('E_DECODE_FAILED', 'Payload or signature base64url decoding failed');
    }
    return fail('E_BAD_SIGNATURE', 'Ed25519 signature verification failed');
  }

  // Check 15: parse attestation from payload
  let attestationParsed: unknown;
  try {
    attestationParsed = JSON.parse(payloadBytes.toString('utf-8'));
  } catch {
    return fail('E_INVALID_ATTESTATION', 'Attestation payload is not valid JSON');
  }

  const attResult = AttestationSchema.safeParse(attestationParsed);
  if (!attResult.success) {
    return fail('E_INVALID_ATTESTATION', `Attestation failed validation: ${attResult.error.message}`);
  }
  const attestation = attResult.data as Attestation;

  // Fix #2: Compare attestation.json on disk to signed payload
  // Signed payload in signature.json is authoritative. attestation.json on disk must match exactly.
  const attestationOnDisk = await readFile(join(vaultDir, 'attestation.json'));
  if (!safeHashCompare(payloadBytes, attestationOnDisk)) {
    return fail('E_INTEGRITY_MISMATCH', 'attestation.json on disk does not match signed payload');
  }

  // Check 16: attestation schema version
  if (!(SUPPORTED_ATTESTATION_VERSIONS as readonly string[]).includes(attestation.schema_version)) {
    return fail('E_UNSUPPORTED_VERSION', `Unsupported attestation schema version: ${attestation.schema_version}`);
  }

  // Check 17: _critical fields
  if (attestation._critical) {
    for (const field of attestation._critical) {
      if (!KNOWN_CRITICAL_FIELDS.includes(field)) {
        return fail('E_UNKNOWN_CRITICAL', `Unrecognized critical field: ${field}`);
      }
    }
  }

  // Check 18: integrity.json hash
  const integrityRaw = await readFile(join(vaultDir, 'integrity.json'));
  const integrityHash = hashData(integrityRaw);
  const expectedHash = parseHashString(attestation.integrity_hash);
  const actualHash = parseHashString(integrityHash);
  if (!safeHashCompare(Buffer.from(expectedHash.hex, 'hex'), Buffer.from(actualHash.hex, 'hex'))) {
    return fail('E_INTEGRITY_MISMATCH', 'integrity.json hash mismatch');
  }

  // Check 19: parse integrity.json
  let integrityParsed: unknown;
  try {
    integrityParsed = JSON.parse(integrityRaw.toString('utf-8'));
  } catch {
    return fail('E_INVALID_INTEGRITY', 'integrity.json is not valid JSON');
  }

  const intResult = IntegritySchema.safeParse(integrityParsed);
  if (!intResult.success) {
    return fail('E_INVALID_INTEGRITY', `Integrity manifest failed validation: ${intResult.error.message}`);
  }
  const integrity = intResult.data;

  // Check 20: integrity schema version
  if (!(SUPPORTED_INTEGRITY_VERSIONS as readonly string[]).includes(integrity.schema_version)) {
    return fail('E_UNSUPPORTED_VERSION', `Unsupported integrity schema version: ${integrity.schema_version}`);
  }

  // Check 21: file hash verification
  // Fix #1: validate that each filePath stays within skillDir (path traversal protection)
  for (const [filePath, expectedFileHash] of Object.entries(integrity.files)) {
    if (!isPathSafe(filePath, skillDir)) {
      return fail('E_INTEGRITY_MISMATCH', `Path traversal detected: ${filePath}`, filePath);
    }
    const fullPath = join(skillDir, filePath);
    let fileData: Buffer;
    try {
      fileData = await readFile(fullPath);
    } catch {
      return fail('E_INTEGRITY_MISMATCH', `File hash mismatch: ${filePath}`, filePath);
    }
    const actualFileHash = hashData(fileData);
    const expParsed = parseHashString(expectedFileHash);
    const actParsed = parseHashString(actualFileHash);
    if (!safeHashCompare(Buffer.from(expParsed.hex, 'hex'), Buffer.from(actParsed.hex, 'hex'))) {
      return fail('E_INTEGRITY_MISMATCH', `File hash mismatch: ${filePath}`, filePath);
    }
  }

  // Check 22: extra files
  const allFiles = await walkFiles(skillDir, skillDir);
  for (const f of allFiles) {
    if (!(f in integrity.files)) {
      return fail('E_EXTRA_FILES', `Undeclared file: ${f}`, f);
    }
  }

  // Parse and validate permissions.json
  let permissions: Permissions | undefined;
  let permRaw: string;
  try {
    permRaw = await readFile(join(vaultDir, 'permissions.json'), 'utf-8');
  } catch {
    return fail('E_INVALID_ENVELOPE', 'Could not read permissions.json');
  }

  let permObj: unknown;
  try {
    permObj = JSON.parse(permRaw);
  } catch {
    return fail('E_INVALID_ENVELOPE', 'permissions.json is not valid JSON');
  }

  const permParsed = PermissionsSchema.safeParse(permObj);
  if (!permParsed.success) {
    return fail('E_INVALID_ENVELOPE', `permissions.json failed validation: ${permParsed.error.message}`);
  }
  permissions = permParsed.data;

  // Verify permissions_hash: canonical(parsed) must match attestation.permissions_hash
  const permCanonical = canonicalizeToBuffer(permissions);
  const permHash = hashData(permCanonical);
  const expectedPermHash = parseHashString(attestation.permissions_hash);
  const actualPermHash = parseHashString(permHash);
  if (!safeHashCompare(Buffer.from(expectedPermHash.hex, 'hex'), Buffer.from(actualPermHash.hex, 'hex'))) {
    return fail('E_INTEGRITY_MISMATCH', 'permissions.json hash mismatch');
  }

  // Check 23: revocation
  let trustLevel: TrustLevel = 'full';

  if (options.context === 'install') {
    const revResult = checkRevocationForInstall(
      attestation.skill.name,
      attestation.skill.version,
      options.revocationList,
      options.trustedKeys,
      options.cachedSequenceNumber
    );
    if (revResult.errors.length > 0) {
      return { valid: false, trustLevel: 'none', warnings: [], errors: revResult.errors };
    }
    trustLevel = revResult.trustLevel;
  } else {
    const revResult = checkRevocationForRuntime(
      attestation.skill.name,
      attestation.skill.version,
      options.revocationList,
      options.trustedKeys,
      options.cachedSequenceNumber,
      options.lastValidRevocationList
    );
    if (revResult.errors.length > 0) {
      return { valid: false, trustLevel: 'none', warnings: revResult.warnings, errors: revResult.errors };
    }
    warnings.push(...revResult.warnings);
    trustLevel = revResult.trustLevel;
  }

  return {
    valid: true,
    trustLevel,
    warnings,
    errors: [],
    attestation,
    permissions,
    keyId: verifiedKeyId,
  };
}

export async function verifySigstoreEnvelope(
  skillDir: string,
  options: SigstoreVerifyOptions
): Promise<SigstoreVerifyResult> {
  const warnings: VerifyWarning[] = [];

  // Check 1: .vault/ exists
  const vaultDir = join(skillDir, VAULT_DIR);
  try {
    await access(vaultDir);
  } catch {
    return sigstoreFail('E_NO_ENVELOPE', '.vault/ directory not found');
  }

  // Check 2: required files (sigstore-bundle.json instead of signature.json)
  for (const f of REQUIRED_VAULT_FILES_SIGSTORE) {
    try {
      await access(join(vaultDir, f));
    } catch {
      return sigstoreFail('E_INCOMPLETE', `Missing required file: ${f}`);
    }
  }

  // Checks 3-7: filesystem safety (same as Ed25519 path)
  const skipHardlink = options.context === 'runtime' && options.skipHardlinkCheck === true;
  const fsCheck = await checkFilesystem(skillDir, { skipHardlinkCheck: skipHardlink });

  const symlinkErrors = fsCheck.errors.filter((e) => e.code === 'E_SYMLINK');
  if (symlinkErrors.length > 0) {
    return { valid: false, trustLevel: 'none', warnings: [], errors: symlinkErrors };
  }

  const hardlinkErrors = fsCheck.errors.filter((e) => e.code === 'E_HARDLINK');
  if (hardlinkErrors.length > 0) {
    return { valid: false, trustLevel: 'none', warnings: [], errors: hardlinkErrors };
  }

  const limitErrors = fsCheck.errors.filter((e) => e.code === 'E_LIMITS');
  if (limitErrors.length > 0) {
    return { valid: false, trustLevel: 'none', warnings: [], errors: limitErrors };
  }

  // Check 8-14 (Sigstore): read bundle + verify signature via Sigstore
  const bundle = await readSigstoreBundle(skillDir);
  if (!bundle) {
    return sigstoreFail('E_INVALID_ENVELOPE', 'Could not read sigstore-bundle.json');
  }

  const attestationOnDisk = await readFile(join(vaultDir, 'attestation.json'));

  // Verify the Sigstore bundle signature + transparency log (no identity constraints).
  // Identity checking is done separately below to support multiple trusted identities.
  let signerInfo;
  try {
    signerInfo = await verifyWithSigstore(bundle, attestationOnDisk, {
      tlogThreshold: 1,
      ctLogThreshold: 0,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return sigstoreFail('E_BAD_SIGNATURE', `Sigstore verification failed: ${msg}`);
  }

  // Identity check: trustedIdentities is required — fail-closed
  if (!options.trustedIdentities?.length) {
    return sigstoreFail(
      'E_UNKNOWN_KEY',
      'Sigstore verification requires at least one trusted identity'
    );
  }

  if (signerInfo.identity === 'unknown' || signerInfo.issuer === 'unknown') {
    return sigstoreFail(
      'E_UNKNOWN_KEY',
      `Could not extract signer identity from Sigstore bundle (identity=${signerInfo.identity}, issuer=${signerInfo.issuer})`
    );
  }

  const identityMatched = options.trustedIdentities.some(
    (ti) => signerInfo.identity === ti.subject && signerInfo.issuer === ti.issuer
  );
  if (!identityMatched) {
    return sigstoreFail(
      'E_UNKNOWN_KEY',
      `Signer identity ${signerInfo.identity} (${signerInfo.issuer}) not in trusted identities`
    );
  }

  // Check 15: parse attestation
  let attestationParsed: unknown;
  try {
    attestationParsed = JSON.parse(attestationOnDisk.toString('utf-8'));
  } catch {
    return sigstoreFail('E_INVALID_ATTESTATION', 'Attestation payload is not valid JSON');
  }

  const attResult = AttestationSchema.safeParse(attestationParsed);
  if (!attResult.success) {
    return sigstoreFail('E_INVALID_ATTESTATION', `Attestation failed validation: ${attResult.error.message}`);
  }
  const attestation = attResult.data as Attestation;

  // Check 16: attestation schema version
  if (!(SUPPORTED_ATTESTATION_VERSIONS as readonly string[]).includes(attestation.schema_version)) {
    return sigstoreFail('E_UNSUPPORTED_VERSION', `Unsupported attestation schema version: ${attestation.schema_version}`);
  }

  // Check 17: _critical fields
  if (attestation._critical) {
    for (const field of attestation._critical) {
      if (!KNOWN_CRITICAL_FIELDS.includes(field)) {
        return sigstoreFail('E_UNKNOWN_CRITICAL', `Unrecognized critical field: ${field}`);
      }
    }
  }

  // Check 18: integrity.json hash
  const integrityRaw = await readFile(join(vaultDir, 'integrity.json'));
  const integrityHash = hashData(integrityRaw);
  const expectedHash = parseHashString(attestation.integrity_hash);
  const actualHash = parseHashString(integrityHash);
  if (!safeHashCompare(Buffer.from(expectedHash.hex, 'hex'), Buffer.from(actualHash.hex, 'hex'))) {
    return sigstoreFail('E_INTEGRITY_MISMATCH', 'integrity.json hash mismatch');
  }

  // Check 19: parse integrity.json
  let integrityParsed: unknown;
  try {
    integrityParsed = JSON.parse(integrityRaw.toString('utf-8'));
  } catch {
    return sigstoreFail('E_INVALID_INTEGRITY', 'integrity.json is not valid JSON');
  }

  const intResult = IntegritySchema.safeParse(integrityParsed);
  if (!intResult.success) {
    return sigstoreFail('E_INVALID_INTEGRITY', `Integrity manifest failed validation: ${intResult.error.message}`);
  }
  const integrity = intResult.data;

  // Check 20: integrity schema version
  if (!(SUPPORTED_INTEGRITY_VERSIONS as readonly string[]).includes(integrity.schema_version)) {
    return sigstoreFail('E_UNSUPPORTED_VERSION', `Unsupported integrity schema version: ${integrity.schema_version}`);
  }

  // Check 21: file hash verification
  for (const [filePath, expectedFileHash] of Object.entries(integrity.files)) {
    if (!isPathSafe(filePath, skillDir)) {
      return sigstoreFail('E_INTEGRITY_MISMATCH', `Path traversal detected: ${filePath}`, filePath);
    }
    const fullPath = join(skillDir, filePath);
    let fileData: Buffer;
    try {
      fileData = await readFile(fullPath);
    } catch {
      return sigstoreFail('E_INTEGRITY_MISMATCH', `File hash mismatch: ${filePath}`, filePath);
    }
    const actualFileHash = hashData(fileData);
    const expParsed = parseHashString(expectedFileHash);
    const actParsed = parseHashString(actualFileHash);
    if (!safeHashCompare(Buffer.from(expParsed.hex, 'hex'), Buffer.from(actParsed.hex, 'hex'))) {
      return sigstoreFail('E_INTEGRITY_MISMATCH', `File hash mismatch: ${filePath}`, filePath);
    }
  }

  // Check 22: extra files
  const allFiles = await walkFiles(skillDir, skillDir);
  for (const f of allFiles) {
    if (!(f in integrity.files)) {
      return sigstoreFail('E_EXTRA_FILES', `Undeclared file: ${f}`, f);
    }
  }

  // Parse and validate permissions.json
  let permissions: Permissions | undefined;
  let permRaw: string;
  try {
    permRaw = await readFile(join(vaultDir, 'permissions.json'), 'utf-8');
  } catch {
    return sigstoreFail('E_INVALID_ENVELOPE', 'Could not read permissions.json');
  }

  let permObj: unknown;
  try {
    permObj = JSON.parse(permRaw);
  } catch {
    return sigstoreFail('E_INVALID_ENVELOPE', 'permissions.json is not valid JSON');
  }

  const permParsed = PermissionsSchema.safeParse(permObj);
  if (!permParsed.success) {
    return sigstoreFail('E_INVALID_ENVELOPE', `permissions.json failed validation: ${permParsed.error.message}`);
  }
  permissions = permParsed.data;

  const permCanonical = canonicalizeToBuffer(permissions);
  const permHash = hashData(permCanonical);
  const expectedPermHash = parseHashString(attestation.permissions_hash);
  const actualPermHash = parseHashString(permHash);
  if (!safeHashCompare(Buffer.from(expectedPermHash.hex, 'hex'), Buffer.from(actualPermHash.hex, 'hex'))) {
    return sigstoreFail('E_INTEGRITY_MISMATCH', 'permissions.json hash mismatch');
  }

  // Check 23: revocation (revocation lists are always Ed25519-signed, even for Sigstore skills)
  let trustLevel: TrustLevel = 'full';
  const revKeyring = options.revocationKeys ?? {};

  if (options.context === 'install') {
    const revResult = checkRevocationForInstall(
      attestation.skill.name,
      attestation.skill.version,
      options.revocationList,
      revKeyring,
      options.cachedSequenceNumber
    );
    if (revResult.errors.length > 0) {
      return { valid: false, trustLevel: 'none', warnings: [], errors: revResult.errors };
    }
    trustLevel = revResult.trustLevel;
  } else {
    const revResult = checkRevocationForRuntime(
      attestation.skill.name,
      attestation.skill.version,
      options.revocationList,
      revKeyring,
      options.cachedSequenceNumber,
      options.lastValidRevocationList
    );
    if (revResult.errors.length > 0) {
      return { valid: false, trustLevel: 'none', warnings: revResult.warnings, errors: revResult.errors };
    }
    warnings.push(...revResult.warnings);
    trustLevel = revResult.trustLevel;
  }

  return {
    valid: true,
    trustLevel,
    warnings,
    errors: [],
    attestation,
    permissions,
    keyId: `sigstore:${signerInfo.identity}`,
    signerIdentity: signerInfo.identity,
    signerIssuer: signerInfo.issuer,
  };
}

function sigstoreFail(code: VerifyError['code'], message: string, file?: string): SigstoreVerifyResult {
  return {
    valid: false,
    trustLevel: 'none',
    warnings: [],
    errors: [{ code, message, file }],
  };
}
