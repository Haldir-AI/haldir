# @haldir/core

Core cryptographic primitives and `.vault/` envelope operations for Haldir.

## What This Package Does

- **Envelope creation:** `createEnvelope()` - signs skills with Ed25519 or Sigstore
- **Envelope verification:** `verifyEnvelope()` - runs 25-check verification contract
- **Cryptographic primitives:** Ed25519 key generation, signing, verification
- **Integrity hashing:** SHA-256 file allowlists with constant-time comparison
- **Canonical JSON:** RFC 8785 deterministic serialization
- **Revocation lists:** Create and verify signed revocation lists
- **Dual-sign support:** `appendSignature()` for co-signing
- **Vetting transparency:** Hash-bound vetting report disclosure

## Installation

```bash
npm install @haldir/core
```

## Usage

### Generate Keys

```typescript
import { generateKeyPair } from '@haldir/core';

const { publicKey, privateKey, keyId } = await generateKeyPair();
// keyId: 32-char hex (128-bit SHA-256 of SPKI DER)
```

### Sign a Skill (Ed25519)

```typescript
import { createEnvelope } from '@haldir/core';

await createEnvelope('/path/to/skill', privateKey, {
  keyId: 'your-key-id',
  skill: {
    name: 'my-skill',
    version: '1.0.0',
    type: 'skill.md'
  }
});

// Creates /path/to/skill/.vault/ with:
//   - signature.json (DSSE v1.0.0 envelope)
//   - attestation.json (signed metadata)
//   - integrity.json (SHA-256 hashes of all files)
//   - permissions.json (declared capabilities)
```

### Sign with Vetting Report (Transparency)

```typescript
await createEnvelope('/path/to/skill', privateKey, {
  keyId: 'your-key-id',
  skill: { name: 'my-skill', version: '1.0.0', type: 'skill.md' },
  vettingReport: {
    schema_version: '1.0',
    vetting_timestamp: new Date().toISOString(),
    pipeline_version: '0.1.0',
    layers: [
      {
        layer: 1,
        name: 'scanner',
        status: 'pass',
        findings: [],
        summary: { critical: 0, high: 0, medium: 0, low: 0 }
      }
    ],
    overall_status: 'pass'
  }
});

// Vetting report hash-bound to attestation (tamper-proof)
// Creates .vault/vetting-report.json (canonical JSON)
```

### Sign a Skill (Sigstore Keyless)

```typescript
import { createKeylessEnvelope } from '@haldir/core';

await createKeylessEnvelope('/path/to/skill', {
  skill: {
    name: 'my-skill',
    version: '1.0.0',
    type: 'skill.md'
  },
  identityToken: process.env.OIDC_TOKEN, // From GitHub Actions, Google, etc.
  vettingReport: optionalVettingReport
});

// Creates /path/to/skill/.vault/ with:
//   - sigstore-bundle.json (Fulcio cert + Rekor proof)
//   - attestation.json, integrity.json, permissions.json
```

### Co-sign (Dual-Sign)

```typescript
import { appendSignature } from '@haldir/core';

await appendSignature('/path/to/skill', secondPrivateKey, 'authority-key-id');

// Adds second signature to existing .vault/signature.json
// Useful for publisher + authority dual-signing
```

### Verify a Skill

```typescript
import { verifyEnvelope } from '@haldir/core';

const result = await verifyEnvelope('/path/to/skill', {
  trustedKeys: {
    'key-id-1': publicKey1,
    'key-id-2': publicKey2
  },
  revocationList: revocationListData,
  context: 'install' // or 'runtime'
});

if (result.valid) {
  console.log(`Trust level: ${result.trustLevel}`); // 'full' | 'degraded'
  console.log(`Signed by: ${result.keyId}`);
  console.log(`Vetting status: ${result.vettingReport?.overall_status}`);
} else {
  console.log(`Errors: ${result.errors.map(e => e.code).join(', ')}`);
}
```

### Revocation Lists

```typescript
import { createRevocationList } from '@haldir/core';

const revocationList = await createRevocationList(
  {
    schema_version: '1.0',
    sequence_number: 42,
    issued_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
    next_update: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    entries: [
      {
        skill_name: 'malicious-skill',
        skill_version: '1.0.0',
        revoked_at: new Date().toISOString(),
        reason: 'credential exfiltration',
        severity: 'critical'
      }
    ]
  },
  revocationPrivateKey
);

// Returns signed revocation list (publish to CDN)
```

## Key Concepts

### Trust Levels

| Level | Meaning |
|-------|---------|
| `full` | Signature valid, integrity passes, revocation list fresh, skill not revoked |
| `degraded` | Signature valid, integrity passes, but revocation list stale/unavailable (runtime context only) |
| `none` | Verification failed - do not load this skill |

### Verification Contexts

| Context | Revocation Policy | Use Case |
|---------|-------------------|----------|
| `install` | Fail-closed (missing/stale list = reject) | Pre-installation verification |
| `runtime` | Fail-open with grace (missing/stale list = degraded trust) | Already-installed skill checks |

### Error Codes

| Code | Meaning |
|------|---------|
| `E_NO_VAULT` | `.vault/` directory not found |
| `E_SIGNATURE_INVALID` | Ed25519 signature verification failed |
| `E_INTEGRITY_MISMATCH` | File hash doesn't match integrity.json |
| `E_EXTRA_FILES` | Undeclared files found (allowlist violation) |
| `E_REVOKED` | Skill appears in revocation list |
| `E_SIGSTORE_INVALID` | Sigstore bundle verification failed |

Full list: see [SPEC.md](../../docs/SPEC.md#error-codes)

## Standards Compliance

- **DSSE v1.0.0** - Signature envelope format
- **RFC 8785** - Canonical JSON serialization
- **RFC 8032** - Ed25519 digital signatures
- **FIPS 180-4** - SHA-256 hashing
- **Sigstore** - Keyless signing (Fulcio + Rekor)

## Type Exports

All TypeScript types are exported:

```typescript
import type {
  Attestation,
  IntegrityManifest,
  Permissions,
  RevocationList,
  VettingReport,
  VerificationResult,
  TrustLevel,
  ErrorCode
} from '@haldir/core';
```

## Security

- **Constant-time comparison** for all hash digests (`crypto.timingSafeEqual`)
- **Symlink rejection** across entire skill directory tree
- **Hard link rejection** on regular files (install context)
- **Size limits**: 10K files, 100MB per file, 500MB total
- **Clock skew tolerance**: 300s on all timestamp comparisons

## See Also

- **[@haldir/cli](../cli)** - Command-line interface
- **[@haldir/sdk](../sdk)** - High-level integration SDK
- **[SPEC.md](../../docs/SPEC.md)** - Full specification (ASAF v1.0)
- **[Root README](../../README.md)** - Quick start guide

## License

Apache 2.0
