# @haldir/sdk

High-level SDK for integrating Haldir verification into agent platforms.

## What This Package Does

Provides a simple, batteries-included API for verifying agent skills. Wraps `@haldir/core` with sensible defaults, automatic key management, and multi-signature support.

## Installation

```bash
npm install @haldir/sdk
```

## Quick Start

```typescript
import { Haldir } from '@haldir/sdk';

// Initialize with trusted keys
const haldir = new Haldir({
  trustedKeys: {
    'publisher-2026': 'ed25519:AAAA...',
    'haldir-prod-2026': 'ed25519:BBBB...'
  }
});

// Verify a skill before installation
const result = await haldir.verify('./skills/my-skill/', {
  context: 'install',
  revocationList,
  cachedSequenceNumber: 41
});

if (result.valid) {
  console.log(`✓ Verified by ${result.keyId}`);
  console.log(`  Trust: ${result.trustLevel}`);
  console.log(`  Vetting: ${result.vettingReport?.overall_status || 'none'}`);
  // Safe to load skill
} else {
  console.log(`✗ Verification failed: ${result.errors[0].message}`);
  // DO NOT load skill
}
```

## API

### Constructor

```typescript
const haldir = new Haldir(options);
```

**Options:**

```typescript
interface HaldirOptions {
  // Ed25519 trusted keys (keyId → public key PEM)
  trustedKeys?: Record<string, string>;

  // Sigstore trusted identities (issuer=subject format)
  trustedIdentities?: string[];

  // Revocation list signing keys (keyId → public key PEM)
  revocationKeys?: Record<string, string>;

  // Enable auto-update of revocation list
  autoUpdateRevocations?: boolean;

  // Revocation list URL
  revocationListUrl?: string;
}
```

### Methods

#### `verify(skillPath, options?)`

Verifies a skill directory.

**Options:**

```typescript
interface VerifyOptions {
  // Verification context
  context?: 'install' | 'runtime'; // default: 'install'

  // Revocation list (optional)
  revocationList?: RevocationList;

  // Cached sequence number (skip if list unchanged)
  cachedSequenceNumber?: number;

  // Override trusted keys for this verification
  trustedKeys?: Record<string, string>;
}
```

**Returns:** `Promise<VerificationResult>`

```typescript
interface VerificationResult {
  valid: boolean;
  trustLevel: 'full' | 'degraded' | 'none';
  keyId?: string;
  warnings: Warning[];
  errors: Error[];
  attestation?: Attestation;
  permissions?: Permissions;
  vettingReport?: VettingReport;
}
```

#### `autoVerify(skillPath, options?)`

Auto-detects Ed25519 or Sigstore and verifies accordingly.

```typescript
const result = await haldir.autoVerify('./my-skill/', {
  context: 'install'
});
```

#### `verifySigstore(skillPath, options?)`

Verifies a Sigstore-signed skill.

```typescript
const result = await haldir.verifySigstore('./my-skill/', {
  trustedIdentities: ['https://github.com/login/oauth=user@example.com'],
  context: 'install'
});
```

## Usage Patterns

### Pre-Install Verification (Fail-Closed)

```typescript
async function installSkill(skillPath: string) {
  const result = await haldir.verify(skillPath, {
    context: 'install',
    revocationList: await fetchRevocationList()
  });

  if (!result.valid) {
    throw new Error(`Skill verification failed: ${result.errors[0].message}`);
  }

  if (result.trustLevel !== 'full') {
    throw new Error(`Insufficient trust level: ${result.trustLevel}`);
  }

  // Safe to load
  await loadSkill(skillPath, result.permissions);
}
```

### Runtime Verification (Fail-Open with Grace)

```typescript
async function checkInstalledSkill(skillPath: string) {
  const result = await haldir.verify(skillPath, {
    context: 'runtime',
    revocationList: cachedRevocationList
  });

  if (!result.valid) {
    console.error(`Skill ${skillPath} is no longer valid`);
    await unloadSkill(skillPath);
    return;
  }

  if (result.trustLevel === 'degraded') {
    console.warn(`Skill ${skillPath} has degraded trust (stale revocation list)`);
    // Still OK to run, but schedule re-check
  }

  if (result.warnings.length > 0) {
    console.warn(`Warnings for ${skillPath}:`, result.warnings);
  }
}
```

### Multi-Signature (Dual-Sign)

```typescript
const haldir = new Haldir({
  trustedKeys: {
    // Trust EITHER publisher OR authority
    'publisher-alice': 'ed25519:AAAA...',
    'haldir-authority': 'ed25519:BBBB...'
  }
});

// Verifies successfully if ANY trusted key signed
const result = await haldir.verify('./skill/');

// Both signatures present? Check attestation
if (result.attestation?.signatures?.length === 2) {
  console.log('Dual-signed by publisher + authority');
}
```

### Sigstore Keyless Verification

```typescript
const haldir = new Haldir({
  trustedIdentities: [
    // Trust specific GitHub repo
    'https://token.actions.githubusercontent.com=https://github.com/org/repo/.github/workflows/sign.yml@refs/heads/main',

    // Trust Google account
    'https://accounts.google.com=user@example.com'
  ]
});

const result = await haldir.verifySigstore('./skill/', {
  context: 'install'
});
```

### Vetting Report Transparency

```typescript
const result = await haldir.verify('./skill/', { context: 'install' });

if (result.vettingReport) {
  console.log(`Vetting status: ${result.vettingReport.overall_status}`);
  console.log(`Pipeline version: ${result.vettingReport.pipeline_version}`);
  console.log(`Vetted at: ${result.vettingReport.vetting_timestamp}`);

  for (const layer of result.vettingReport.layers) {
    console.log(`Layer ${layer.layer} (${layer.name}): ${layer.status}`);
    if (layer.findings.length > 0) {
      console.log(`  ${layer.findings.length} findings`);
    }
  }

  if (result.vettingReport.publisher_note) {
    console.log(`Publisher note: ${result.vettingReport.publisher_note}`);
  }
}
```

## Integration Examples

### Express Middleware

```typescript
import { Haldir } from '@haldir/sdk';

const haldir = new Haldir({ trustedKeys: TRUSTED_KEYS });

function verifySkillMiddleware(req, res, next) {
  const skillPath = req.body.skillPath;

  haldir.verify(skillPath, { context: 'install' })
    .then(result => {
      if (result.valid) {
        req.verification = result;
        next();
      } else {
        res.status(403).json({ error: result.errors[0].message });
      }
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
}
```

### Agent Skill Loader

```typescript
class SkillManager {
  private haldir: Haldir;

  constructor() {
    this.haldir = new Haldir({
      trustedKeys: PRODUCTION_KEYS,
      revocationListUrl: 'https://haldir.ai/.well-known/haldir-revocation.json'
    });
  }

  async loadSkill(skillPath: string) {
    const result = await this.haldir.verify(skillPath, {
      context: 'install',
      revocationList: await this.fetchRevocationList()
    });

    if (!result.valid) {
      throw new Error(`Verification failed: ${result.errors[0].code}`);
    }

    // Enforce permissions from attestation
    await this.enforcePermissions(skillPath, result.permissions);

    // Load skill
    return await this.importSkill(skillPath);
  }
}
```

## Error Handling

```typescript
try {
  const result = await haldir.verify('./skill/');

  if (!result.valid) {
    // Verification failed - check errors
    for (const error of result.errors) {
      switch (error.code) {
        case 'E_NO_VAULT':
          console.error('Skill not signed');
          break;
        case 'E_SIGNATURE_INVALID':
          console.error('Invalid signature');
          break;
        case 'E_INTEGRITY_MISMATCH':
          console.error(`File tampered: ${error.file}`);
          break;
        case 'E_REVOKED':
          console.error('Skill revoked');
          break;
        default:
          console.error(error.message);
      }
    }
  }

  // Check warnings (non-fatal)
  for (const warning of result.warnings) {
    console.warn(`${warning.code}: ${warning.message}`);
  }

} catch (err) {
  // Unexpected errors (filesystem, parsing, etc.)
  console.error('Verification error:', err);
}
```

## TypeScript Support

Full TypeScript types included:

```typescript
import type {
  Haldir,
  HaldirOptions,
  VerifyOptions,
  VerificationResult,
  TrustLevel,
  ErrorCode,
  WarningCode
} from '@haldir/sdk';
```

## Performance

- **Typical verification:** 50-100ms
- **Large skills (10K files):** <5s
- **Revocation check:** <10ms (in-memory)
- **Sigstore verification:** 200-500ms (includes Rekor lookup)

## See Also

- **[@haldir/core](../core)** - Low-level crypto primitives
- **[@haldir/cli](../cli)** - Command-line interface
- **[SPEC.md](../../docs/SPEC.md)** - Full specification
- **[Root README](../../README.md)** - Quick start guide

## License

Apache 2.0
