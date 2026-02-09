import { canonicalize } from './canonical.js';
import { sign as ed25519Sign, verify as ed25519Verify, base64urlEncode, base64urlDecode } from './crypto.js';
import { RevocationListSchema } from './schemas.js';
import { CLOCK_SKEW_TOLERANCE, RUNTIME_GRACE_HOURS, SUPPORTED_REVOCATION_VERSIONS } from './types.js';
import type {
  SignedRevocationList,
  RevocationEntry,
  RevocationVerifyResult,
  RevocationCheckResult,
  KeyRing,
  VerifyError,
  VerifyWarning,
} from './types.js';

export function createRevocationList(
  entries: RevocationEntry[],
  privateKeyPem: string,
  keyId: string,
  sequenceNumber: number,
  expiresInHours = 24
): SignedRevocationList {
  const now = new Date();
  const expires = new Date(now.getTime() + expiresInHours * 3600_000);
  const nextUpdate = new Date(now.getTime() + 1800_000); // 30 min

  const payload = {
    schema_version: '1.0' as const,
    sequence_number: sequenceNumber,
    issued_at: now.toISOString(),
    expires_at: expires.toISOString(),
    next_update: nextUpdate.toISOString(),
    entries,
  };

  const canonical = canonicalize(payload);
  const sigBytes = ed25519Sign(Buffer.from(canonical, 'utf-8'), privateKeyPem);

  return {
    ...payload,
    signature: {
      keyid: keyId,
      sig: base64urlEncode(sigBytes),
    },
  };
}

export function verifyRevocationList(
  list: SignedRevocationList,
  trustedKeys: KeyRing
): RevocationVerifyResult {
  const errors: VerifyError[] = [];

  const parseResult = RevocationListSchema.safeParse(list);
  if (!parseResult.success) {
    errors.push({ code: 'E_REVOCATION_STALE', message: `Revocation list schema invalid: ${parseResult.error.message}` });
    return { valid: false, errors };
  }

  if (!(SUPPORTED_REVOCATION_VERSIONS as readonly string[]).includes(list.schema_version)) {
    errors.push({ code: 'E_UNSUPPORTED_VERSION', message: `Unsupported revocation schema version: ${list.schema_version}` });
    return { valid: false, errors };
  }

  const pubKey = trustedKeys[list.signature.keyid];
  if (!pubKey) {
    errors.push({ code: 'E_UNKNOWN_KEY', message: `Unknown revocation signing key: ${list.signature.keyid}` });
    return { valid: false, errors };
  }

  const { signature: _, ...payloadObj } = list;
  const canonical = canonicalize(payloadObj);
  let sigBytes: Buffer;
  try {
    sigBytes = base64urlDecode(list.signature.sig);
  } catch {
    errors.push({ code: 'E_BAD_SIGNATURE', message: 'Revocation signature decode failed' });
    return { valid: false, errors };
  }

  if (!ed25519Verify(Buffer.from(canonical, 'utf-8'), sigBytes, pubKey)) {
    errors.push({ code: 'E_BAD_SIGNATURE', message: 'Revocation list signature verification failed' });
    return { valid: false, errors };
  }

  if (list.sequence_number < 1) {
    errors.push({ code: 'E_REVOCATION_STALE', message: 'Revocation sequence number must be positive' });
    return { valid: false, errors };
  }

  const issuedAt = new Date(list.issued_at).getTime();
  const expiresAt = new Date(list.expires_at).getTime();
  if (issuedAt >= expiresAt + CLOCK_SKEW_TOLERANCE * 1000) {
    errors.push({ code: 'E_REVOCATION_STALE', message: 'issued_at >= expires_at' });
    return { valid: false, errors };
  }

  return { valid: true, errors: [] };
}

export function isRevoked(name: string, version: string, list: SignedRevocationList): boolean {
  return list.entries.some(
    (e) => e.name === name && (e.versions.includes('*') || e.versions.includes(version))
  );
}

function isExpired(list: SignedRevocationList, graceHours = 0): boolean {
  const now = Date.now();
  const expiresAt = new Date(list.expires_at).getTime();
  const graceMs = graceHours * 3600_000;
  const skewMs = CLOCK_SKEW_TOLERANCE * 1000;
  return now > expiresAt + graceMs + skewMs;
}

export function checkRevocationForInstall(
  name: string,
  version: string,
  list: SignedRevocationList | undefined,
  trustedKeys: KeyRing,
  cachedSeq?: number
): RevocationCheckResult {
  const errors: VerifyError[] = [];

  if (!list) {
    errors.push({ code: 'E_REVOCATION_STALE', message: 'No revocation list provided for install' });
    return { trustLevel: 'none', warnings: [], errors };
  }

  const sigResult = verifyRevocationList(list, trustedKeys);
  if (!sigResult.valid) {
    errors.push({ code: 'E_REVOCATION_STALE', message: 'Revocation list signature invalid' });
    return { trustLevel: 'none', warnings: [], errors };
  }

  if (isExpired(list)) {
    errors.push({ code: 'E_REVOCATION_STALE', message: 'Revocation list expired' });
    return { trustLevel: 'none', warnings: [], errors };
  }

  if (cachedSeq !== undefined && list.sequence_number <= cachedSeq) {
    errors.push({ code: 'E_REVOCATION_STALE', message: 'Revocation list sequence number rollback detected' });
    return { trustLevel: 'none', warnings: [], errors };
  }

  if (isRevoked(name, version, list)) {
    errors.push({ code: 'E_REVOKED', message: `Skill ${name}@${version} has been revoked` });
    return { trustLevel: 'none', warnings: [], errors };
  }

  return {
    trustLevel: 'full',
    warnings: [],
    errors: [],
    newSequenceNumber: list.sequence_number,
  };
}

export function checkRevocationForRuntime(
  name: string,
  version: string,
  list: SignedRevocationList | undefined,
  trustedKeys: KeyRing,
  cachedSeq?: number,
  lastValidList?: SignedRevocationList
): RevocationCheckResult {
  const warnings: VerifyWarning[] = [];
  const errors: VerifyError[] = [];

  // Verify lastValidList signature + freshness before trusting its entries (defense-in-depth).
  // Reject forged lists (sig check) and stale lists (expired beyond runtime grace).
  const verifiedLastValid = lastValidList
    && verifyRevocationList(lastValidList, trustedKeys).valid
    && !isExpired(lastValidList, RUNTIME_GRACE_HOURS)
    ? lastValidList
    : undefined;

  if (!list) {
    if (verifiedLastValid && isRevoked(name, version, verifiedLastValid)) {
      errors.push({ code: 'E_REVOKED', message: `Skill ${name}@${version} has been revoked` });
      return { trustLevel: 'none', warnings, errors };
    }
    warnings.push({ code: 'W_REVOCATION_UNAVAILABLE', message: 'No revocation list available at runtime' });
    return { trustLevel: 'degraded', warnings, errors };
  }

  const sigResult = verifyRevocationList(list, trustedKeys);
  if (!sigResult.valid) {
    if (verifiedLastValid && isRevoked(name, version, verifiedLastValid)) {
      errors.push({ code: 'E_REVOKED', message: `Skill ${name}@${version} has been revoked` });
      return { trustLevel: 'none', warnings, errors };
    }
    warnings.push({ code: 'W_REVOCATION_SIG_INVALID', message: verifiedLastValid
      ? 'Revocation list signature invalid, using last valid'
      : 'Revocation list signature invalid, no valid fallback available' });
    return { trustLevel: 'degraded', warnings, errors };
  }

  if (cachedSeq !== undefined && list.sequence_number <= cachedSeq) {
    if (verifiedLastValid && isRevoked(name, version, verifiedLastValid)) {
      errors.push({ code: 'E_REVOKED', message: `Skill ${name}@${version} has been revoked` });
      return { trustLevel: 'none', warnings, errors };
    }
    return { trustLevel: 'degraded', warnings, errors };
  }

  if (isRevoked(name, version, list)) {
    errors.push({ code: 'E_REVOKED', message: `Skill ${name}@${version} has been revoked` });
    return { trustLevel: 'none', warnings, errors };
  }

  if (isExpired(list)) {
    errors.push({ code: 'E_REVOCATION_STALE', message: 'Revocation list expired beyond grace period' });
    return { trustLevel: 'none', warnings, errors };
  }

  if (isExpiredWithinGrace(list)) {
    warnings.push({ code: 'W_REVOCATION_STALE', message: 'Revocation list expired but within grace period' });
    return {
      trustLevel: 'degraded',
      warnings,
      errors,
      newSequenceNumber: list.sequence_number,
    };
  }

  return {
    trustLevel: 'full',
    warnings,
    errors,
    newSequenceNumber: list.sequence_number,
  };
}

function isExpiredWithinGrace(list: SignedRevocationList): boolean {
  const now = Date.now();
  const expiresAt = new Date(list.expires_at).getTime();
  const skewMs = CLOCK_SKEW_TOLERANCE * 1000;
  const graceMs = RUNTIME_GRACE_HOURS * 3600_000;
  return now > expiresAt + skewMs && now <= expiresAt + graceMs + skewMs;
}
