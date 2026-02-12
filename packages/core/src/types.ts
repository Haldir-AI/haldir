// --- Constants ---

export const MAX_FILES = 10_000;
export const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB
export const MAX_TOTAL_SIZE = 500 * 1024 * 1024; // 500MB
export const CLOCK_SKEW_TOLERANCE = 300; // seconds (5 min)
export const RUNTIME_GRACE_HOURS = 24;
export const HALDIR_PAYLOAD_TYPE = 'application/vnd.haldir.attestation+json';
export const SUPPORTED_SIGNATURE_VERSIONS = ['1.0'] as const;
export const SUPPORTED_ATTESTATION_VERSIONS = ['1.0'] as const;
export const SUPPORTED_INTEGRITY_VERSIONS = ['1.0'] as const;
export const SUPPORTED_PERMISSIONS_VERSIONS = ['1.0'] as const;
export const SUPPORTED_REVOCATION_VERSIONS = ['1.0'] as const;
export const VAULT_DIR = '.vault';

// --- Error & Warning Codes ---

export type ErrorCode =
  | 'E_NO_ENVELOPE'
  | 'E_INCOMPLETE'
  | 'E_SYMLINK'
  | 'E_HARDLINK'
  | 'E_LIMITS'
  | 'E_INVALID_ENVELOPE'
  | 'E_UNSUPPORTED_VERSION'
  | 'E_UNKNOWN_KEY'
  | 'E_DECODE_FAILED'
  | 'E_BAD_SIGNATURE'
  | 'E_INVALID_ATTESTATION'
  | 'E_UNKNOWN_CRITICAL'
  | 'E_INVALID_INTEGRITY'
  | 'E_INTEGRITY_MISMATCH'
  | 'E_EXTRA_FILES'
  | 'E_REVOKED'
  | 'E_REVOCATION_STALE';

export type WarningCode =
  | 'W_REVOCATION_UNAVAILABLE'
  | 'W_REVOCATION_STALE'
  | 'W_REVOCATION_SIG_INVALID';

export type TrustLevel = 'full' | 'degraded' | 'none';

// --- Crypto Types ---

export interface KeyPair {
  publicKey: string;  // PEM
  privateKey: string; // PEM
  keyId: string;
}

export type KeyRing = Record<string, string>; // keyId → PEM public key

// --- .vault/ File Types ---

export interface DSSESignature {
  keyid: string;
  sig: string; // base64url
}

export interface SignatureEnvelope {
  schema_version: string;
  payloadType: string;
  payload: string; // base64url
  signatures: DSSESignature[];
}

export interface Attestation {
  schema_version: string;
  skill: {
    name: string;
    version: string;
    type: string;
  };
  integrity_hash: string;    // sha256:<64hex>
  permissions_hash: string;  // sha256:<64hex>
  signed_at: string;         // ISO 8601
  _critical?: string[];
  [key: string]: unknown;
}

export interface IntegrityManifest {
  schema_version: string;
  algorithm: string;
  files: Record<string, string>; // relativePath → sha256:<64hex>
  generated_at: string;
}

export interface Permissions {
  schema_version: string;
  declared: {
    filesystem?: {
      read?: string[];
      write?: string[];
    };
    network?: string | string[];
    exec?: string[];
    agent_capabilities?: {
      memory_read?: boolean;
      memory_write?: boolean;
      spawn_agents?: boolean;
      modify_system_prompt?: boolean;
    };
  };
}

// --- Verification Types ---

export interface VerifyOptions {
  trustedKeys: KeyRing;
  revocationList?: SignedRevocationList;
  lastValidRevocationList?: SignedRevocationList;
  cachedSequenceNumber?: number;
  context: 'install' | 'runtime';
  skipHardlinkCheck?: boolean;
}

export interface VerifyError {
  code: ErrorCode;
  message: string;
  file?: string;
}

export interface VerifyWarning {
  code: WarningCode;
  message: string;
}

export interface VerifyResult {
  valid: boolean;
  trustLevel: TrustLevel;
  warnings: VerifyWarning[];
  errors: VerifyError[];
  attestation?: Attestation;
  permissions?: Permissions;
  keyId?: string;
}

export interface CLIOutput {
  valid: boolean;
  trustLevel: TrustLevel;
  keyId: string | null;
  warnings: Array<{ code: string; message: string }>;
  errors: Array<{ code: string; message: string; file?: string }>;
  attestation: Attestation | null;
  permissions: Permissions | null;
}

// --- Revocation Types ---

export interface RevocationEntry {
  name: string;
  versions: string[];
  revoked_at: string;
  reason: string;
  severity: string;
}

export interface SignedRevocationList {
  schema_version: string;
  sequence_number: number;
  issued_at: string;
  expires_at: string;
  next_update: string;
  entries: RevocationEntry[];
  signature: {
    keyid: string;
    sig: string; // base64url
  };
}

export interface RevocationVerifyResult {
  valid: boolean;
  errors: VerifyError[];
}

export interface RevocationCheckResult {
  trustLevel: TrustLevel;
  warnings: VerifyWarning[];
  errors: VerifyError[];
  newSequenceNumber?: number;
}

// --- Envelope Creation Types ---

export interface EnvelopeOptions {
  keyId?: string;
  skill: {
    name: string;
    version: string;
    type: string;
  };
  permissions?: Permissions['declared'];
}

export interface KeylessEnvelopeOptions {
  skill: {
    name: string;
    version: string;
    type: string;
  };
  permissions?: Permissions['declared'];
  identityToken?: string;
  fulcioURL?: string;
  rekorURL?: string;
}

// --- Sigstore Types ---

export interface SigstoreVerifyOptions {
  trustedIdentities?: TrustedIdentity[];
  revocationKeys?: KeyRing;
  revocationList?: SignedRevocationList;
  lastValidRevocationList?: SignedRevocationList;
  cachedSequenceNumber?: number;
  context: 'install' | 'runtime';
  skipHardlinkCheck?: boolean;
}

export interface TrustedIdentity {
  issuer: string;
  subject: string;
}

export interface SigstoreVerifyResult extends VerifyResult {
  signerIdentity?: string;
  signerIssuer?: string;
  transparencyLogId?: string;
}

// --- Filesystem Types ---

export interface WalkOptions {
  skipHardlinkCheck?: boolean;
}

export interface FilesystemCheckResult {
  valid: boolean;
  errors: VerifyError[];
  fileCount: number;
  totalSize: number;
}
