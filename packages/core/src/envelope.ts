import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { canonicalizeToBuffer } from './canonical.js';
import { encodePAE } from './pae.js';
import { sign as ed25519Sign, verify as ed25519Verify, hashData, deriveKeyId, base64urlEncode, base64urlDecode } from './crypto.js';
import { checkFilesystem, hashDirectory } from './integrity.js';
import { signWithSigstore, writeSigstoreBundle } from './sigstore.js';
import { SignatureEnvelopeSchema } from './schemas.js';
import { VAULT_DIR, HALDIR_PAYLOAD_TYPE } from './types.js';
import type {
  EnvelopeOptions,
  KeylessEnvelopeOptions,
  SignatureEnvelope,
  Attestation,
  IntegrityManifest,
  Permissions,
  KeyRing,
} from './types.js';

async function buildSkillMetadata(
  skillDir: string,
  skill: { name: string; version: string; type: string },
  permissions?: Permissions['declared']
): Promise<{
  vaultDir: string;
  attestationBytes: Buffer;
  permissionsObj: Permissions;
}> {
  const fsCheck = await checkFilesystem(skillDir);
  if (!fsCheck.valid) {
    const msgs = fsCheck.errors.map((e) => `${e.code}: ${e.message}`).join('; ');
    throw new Error(`Filesystem check failed: ${msgs}`);
  }

  const vaultDir = join(skillDir, VAULT_DIR);
  await mkdir(vaultDir, { recursive: true });

  const files = await hashDirectory(skillDir);
  const integrityObj: IntegrityManifest = {
    schema_version: '1.0',
    algorithm: 'sha256',
    files,
    generated_at: new Date().toISOString(),
  };
  const integrityBytes = canonicalizeToBuffer(integrityObj);
  await writeFile(join(vaultDir, 'integrity.json'), integrityBytes);

  const permissionsObj: Permissions = {
    schema_version: '1.0',
    declared: permissions ?? {
      filesystem: { read: [], write: [] },
      network: 'none',
      exec: [],
      agent_capabilities: {
        memory_read: false,
        memory_write: false,
        spawn_agents: false,
        modify_system_prompt: false,
      },
    },
  };
  const permissionsCanonical = canonicalizeToBuffer(permissionsObj);
  const permissionsHash = hashData(permissionsCanonical);

  const integrityHash = hashData(integrityBytes);
  const attestationObj: Attestation = {
    schema_version: '1.0',
    skill,
    integrity_hash: integrityHash,
    permissions_hash: permissionsHash,
    signed_at: new Date().toISOString(),
  };
  const attestationBytes = canonicalizeToBuffer(attestationObj);
  await writeFile(join(vaultDir, 'attestation.json'), attestationBytes);

  await writeFile(
    join(vaultDir, 'permissions.json'),
    JSON.stringify(permissionsObj, null, 2) + '\n'
  );

  return { vaultDir, attestationBytes, permissionsObj };
}

export async function createEnvelope(
  skillDir: string,
  privateKeyPem: string,
  options: EnvelopeOptions
): Promise<void> {
  const { vaultDir, attestationBytes } = await buildSkillMetadata(
    skillDir,
    options.skill,
    options.permissions
  );

  const paeBuffer = encodePAE(HALDIR_PAYLOAD_TYPE, attestationBytes);
  const signature = ed25519Sign(paeBuffer, privateKeyPem);
  const keyId = options.keyId ?? deriveKeyId(privateKeyPem);

  const signatureEnvelope: SignatureEnvelope = {
    schema_version: '1.0',
    payloadType: HALDIR_PAYLOAD_TYPE,
    payload: base64urlEncode(attestationBytes),
    signatures: [
      {
        keyid: keyId,
        sig: base64urlEncode(signature),
      },
    ],
  };
  await writeFile(
    join(vaultDir, 'signature.json'),
    JSON.stringify(signatureEnvelope, null, 2) + '\n'
  );
}

export async function createKeylessEnvelope(
  skillDir: string,
  options: KeylessEnvelopeOptions
): Promise<void> {
  const { attestationBytes } = await buildSkillMetadata(
    skillDir,
    options.skill,
    options.permissions
  );

  const bundle = await signWithSigstore(attestationBytes, {
    identityToken: options.identityToken,
    fulcioURL: options.fulcioURL,
    rekorURL: options.rekorURL,
  });

  await writeSigstoreBundle(skillDir, bundle);
}

export async function appendSignature(
  skillDir: string,
  privateKeyPem: string,
  keyId?: string,
  trustedKeys?: KeyRing,
): Promise<void> {
  const vaultDir = join(skillDir, VAULT_DIR);
  const sigPath = join(vaultDir, 'signature.json');

  const raw = await readFile(sigPath, 'utf-8');
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('Invalid signature.json: not valid JSON');
  }
  const result = SignatureEnvelopeSchema.safeParse(parsed);
  if (!result.success) {
    throw new Error(`Invalid signature.json: ${result.error.message}`);
  }
  const envelope = result.data as SignatureEnvelope;

  const payloadBytes = base64urlDecode(envelope.payload);
  const paeBuffer = encodePAE(envelope.payloadType, payloadBytes);

  if (!trustedKeys || Object.keys(trustedKeys).length === 0) {
    throw new Error('Cannot cosign: trustedKeys are required to verify existing signatures before co-signing');
  }

  let anyVerified = false;
  for (const sigEntry of envelope.signatures) {
    const pubKey = trustedKeys[sigEntry.keyid];
    if (!pubKey) continue;
    try {
      const sigBytes = base64urlDecode(sigEntry.sig);
      if (ed25519Verify(paeBuffer, sigBytes, pubKey)) {
        anyVerified = true;
        break;
      }
    } catch {
      continue;
    }
  }
  if (!anyVerified) {
    throw new Error('Cannot cosign: no existing signature verified against provided trusted keys');
  }

  const signature = ed25519Sign(paeBuffer, privateKeyPem);
  const resolvedKeyId = keyId ?? deriveKeyId(privateKeyPem);

  if (envelope.signatures.some((s) => s.keyid === resolvedKeyId)) {
    throw new Error(`Key ID "${resolvedKeyId}" already has a signature in this envelope`);
  }

  envelope.signatures.push({
    keyid: resolvedKeyId,
    sig: base64urlEncode(signature),
  });

  await writeFile(sigPath, JSON.stringify(envelope, null, 2) + '\n');
}
