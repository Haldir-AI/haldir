# Haldir

**HTTPS for AI agents** — Cryptographic signing, verification, and revocation for agent skills and MCP servers.

Named after the March-warden of Lothlorien — nothing enters without his inspection.

## The Problem

Agent skills are distributed without integrity verification, publisher authentication, or revocation capability. In February 2026, security researchers discovered 341 malicious skills (12% of ClawHub registry) deploying credential stealers, reverse shells, and prompt injection payloads. Independent analysis found prompt injection in 36% of skills across major registries.

No existing agent framework or registry implements cryptographic signing at the skill package level.

## What Haldir Does

Haldir places a `.vault/` security envelope alongside your skill files:

```
my-skill/
├── SKILL.md
├── skill.js
└── .vault/
    ├── signature.json      # DSSE-derived envelope (Ed25519 signature, modified PAE)
    ├── attestation.json    # Signed metadata (canonical JSON, RFC 8785)
    ├── integrity.json      # SHA-256 hash of every file (allowlist)
    └── permissions.json    # Declared capabilities
```

Sigstore keyless signing is also supported — sign with your GitHub/Google identity, no key files needed:

```
my-skill/
├── SKILL.md
├── skill.js
└── .vault/
    ├── sigstore-bundle.json  # Sigstore bundle (keyless)
    ├── attestation.json      # Signed metadata (canonical JSON, RFC 8785)
    ├── integrity.json        # SHA-256 hash of every file (allowlist)
    └── permissions.json      # Declared capabilities
```

This gives you:

- **Tamper detection** — any modified, added, or removed file is caught
- **Publisher authentication** — verify who signed (Ed25519 key or OIDC identity)
- **Keyless signing** — Sigstore integration, no private key files to manage
- **Transparency log** — every Sigstore signature recorded in Rekor
- **Dual-sign** — publisher signs + authority co-signs (multi-party trust)
- **Instant revocation** — signed revocation lists disable compromised skills
- **Framework-agnostic** — works with SKILL.md, MCP servers, or any directory

## Quick Start

### Install

```bash
# Global CLI
npm install -g @haldir/cli

# Or use directly
npx @haldir/cli
```

### Generate Keys

```bash
haldir keygen --output ~/.haldir/keys

# Creates:
#   haldir.key   — private key (keep secret)
#   haldir.pub   — public key (distribute to consumers)
#   haldir.keyid — key identifier (32-char hex)
```

### Sign a Skill

```bash
# Ed25519 (offline, key-based)
haldir sign ./my-skill --key ~/.haldir/keys/haldir.key --name my-skill --skill-version 1.0.0

# Sigstore keyless (OIDC-based, no key files)
haldir sign ./my-skill --keyless --name my-skill --skill-version 1.0.0
```

This creates the `.vault/` envelope. Distribute `my-skill/` including `.vault/`.

### Co-sign a Skill (Dual-Sign)

```bash
haldir cosign ./my-skill --key authority.key
```

Adds a second signature to an existing `.vault/`. Useful for publisher + authority dual-signing.

### Verify a Skill

```bash
# Ed25519 verification
haldir verify ./my-skill --key publisher.pub --context install --revocation revocation.json

# Sigstore verification (auto-detected from sigstore-bundle.json)
haldir verify ./my-skill --keyless --context install

# Pin trusted identity for Sigstore
haldir verify ./my-skill --keyless \
  --trusted-identity "https://accounts.google.com=user@example.com" \
  --context install

# Runtime context (graceful — warns if revocation list is stale)
haldir verify ./my-skill --key publisher.pub --context runtime
```

Output is stable JSON:

```json
{
  "valid": true,
  "trustLevel": "full",
  "keyId": "a1b2c3d4e5f6789012345678901234567890abcd",
  "warnings": [],
  "errors": [],
  "attestation": { "..." },
  "permissions": { "..." }
}
```

### Revoke a Skill

```bash
haldir revoke my-skill@1.0.0 \
  --key ~/.haldir/keys/haldir.key \
  --reason "credential exfiltration" \
  --list revocation.json
```

### Inspect (No Verification)

```bash
haldir inspect ./my-skill
```

### Run Built-in Tests

```bash
haldir test
```

Runs 7 end-to-end tests covering keygen, signing, verification, tamper detection, extra file detection, wrong key rejection, and revocation enforcement.

## SDK

For embedding verification in agent platforms:

```typescript
import { Haldir } from '@haldir/sdk';

const haldir = new Haldir({
  trustedKeys: { 'prod-key-2026': PUBLIC_KEY }
});

// Verify for install (fail-closed revocation)
const result = await haldir.verify('./skills/my-skill/', {
  context: 'install',
  revocationList,
  cachedSequenceNumber: 41
});

if (result.valid) {
  console.log(`Verified by ${result.keyId}, trust: ${result.trustLevel}`);
} else {
  console.log(`Rejected: ${result.errors[0].code}`);
}
```

### Trust Levels

| Level | Meaning |
|-------|---------|
| `full` | Signature valid, integrity passes, revocation list fresh and skill not revoked |
| `degraded` | Signature valid, integrity passes, but revocation list stale or unavailable (runtime only) |
| `none` | Verification failed — do not load this skill |

## CLI Reference

| Command | Description | Exit Codes |
|---------|-------------|------------|
| `haldir keygen [--output <dir>]` | Generate Ed25519 keypair | 0 / 2 |
| `haldir sign <dir> --key <path> [--keyless] [--name <n>] [--skill-version <v>]` | Create `.vault/` envelope | 0 / 1 / 2 |
| `haldir cosign <dir> --key <path>` | Add co-signature to existing `.vault/` | 0 / 1 / 2 |
| `haldir verify <dir> [--key <path>] [--keyless] [--trusted-identity <issuer=subject>] [--context install\|runtime] [--revocation <path>]` | Verify envelope | 0 / 1 / 2 |
| `haldir inspect <dir>` | Display envelope contents (no verification) | 0 / 2 |
| `haldir revoke <name@ver> --key <path> --reason <text> --list <path>` | Add to revocation list | 0 / 2 |
| `haldir test` | Run built-in end-to-end test suite | 0 / 1 |

Exit codes: 0 = success, 1 = verification failed, 2 = usage error.

The verify command auto-detects Ed25519 or Sigstore verification based on whether `sigstore-bundle.json` or `signature.json` exists in `.vault/`.

## Verification Contract

Haldir runs 25 ordered checks. The first failure terminates verification (fail-fast):

1. `.vault/` directory exists
2. All 4 required files present
3. No symlinks anywhere in skill directory
4. No hard links on regular files (install context)
5. File count within limits (10,000)
6. No individual file exceeds 100MB
7. Total size within 500MB
8. Signature envelope schema valid
9. Schema version supported
10. At least one signature matches a trusted key
11. Payload base64url decodes correctly
12. PAE construction (DSSE v1.0.0)
13. Signature base64url decodes to 64 bytes
14. Ed25519 signature verifies
15. Attestation JSON parses and validates
16. Attestation schema version supported
17. No unrecognized critical fields
18. integrity.json hash matches attestation.integrity_hash
19. Integrity manifest parses and validates
20. Integrity schema version supported
21. Every file hash matches (constant-time comparison)
22. No undeclared files (allowlist enforcement)
23. Revocation check (policy depends on context)
24. permissions.json hash matches attestation.permissions_hash
25. Attestation.json on disk matches signed payload

## Revocation Policies

| Context | Policy | Behavior |
|---------|--------|----------|
| **install** | Fail-closed | No valid revocation list = reject. Stale list = reject. Revoked = reject. |
| **runtime** | Fail-open with grace | No list = degraded trust + warning. Stale within 24h = degraded. Revoked = reject immediately. |

## Standards

| Standard | Version | Usage |
|----------|---------|-------|
| [DSSE](https://github.com/secure-systems-lab/dsse) | v1.0.0 (modified PAE) | Envelope format. PAE uses ASCII decimal lengths instead of INT64LE — not interoperable with generic DSSE verifiers. See [SPEC.md §PAE](docs/SPEC.md). |
| [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) | JCS | Canonical JSON serialization |
| [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) | Ed25519 | Digital signatures |
| [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final) | SHA-256 | File integrity hashing |
| [Sigstore](https://sigstore.dev) | v4.x | Keyless signing (Fulcio + Rekor) |

## Packages

| Package | Description |
|---------|-------------|
| `@haldir/core` | Crypto, `.vault/` envelope creation, verification engine |
| `@haldir/cli` | Command-line tool |
| `@haldir/sdk` | Verification SDK for agent platforms |
| `@haldir/scanner` | Static analysis — threat pattern detection (Layer 1) |
| `@haldir/auditor` | Dependency audit — pinning, CVEs, supply chain (Layer 2) |
| `@haldir/sandbox` | Isolated execution — behavior monitoring (Layer 3) |
| `@haldir/reviewer` | Dual-LLM semantic audit (Layer 4) |
| `@haldir/pipeline` | 5-layer vetting orchestrator |
| `@haldir/enforcer` | Runtime permission enforcement (Node.js + macOS sandbox) |
| `@haldir/registry` | Registry API — submission, tiers, federation |
| `@haldir/scheduler` | Periodic rescan pipeline |

## Current Trust Model (v0.1)

Haldir v0.1 supports two signing modes:

**Ed25519 (key-based)**
- Publishers generate their own Ed25519 keys via `haldir keygen`
- Publishers sign skills with their private key
- Public keys distributed out-of-band (manual)
- Consumers verify against keys they explicitly trust

**Sigstore (keyless)**
- Publishers sign with their OIDC identity (GitHub, Google)
- No key files — Fulcio issues ephemeral certificates
- Signatures recorded in Rekor transparency log (public, auditable)
- Consumers pin trusted identities (issuer + subject)

**Dual-sign** — a publisher signs (authorship), then an authority co-signs (vetting passed). Consumers trust the authority key and don't need to know every publisher.

A 5-layer vetting pipeline (static analysis, dependency audit, sandbox execution, dual-LLM review, pipeline orchestrator), runtime permission enforcer, and registry API are built and tested. See the [roadmap](docs/ROADMAP.md) for what's next.

## Development

```bash
# Prerequisites
node >= 20.0.0
pnpm >= 9.0.0

# Setup
pnpm install

# Build all packages
pnpm build

# Run all tests (687 across 44 test files)
pnpm test

# Run CLI test suite (7 built-in tests)
pnpm test:cli

# Type check
pnpm lint
```

## Specification

The [Agent Skill Attestation Format (ASAF)](docs/SPEC.md) is an open specification (Apache 2.0) that defines the `.vault/` envelope format, signing procedure, verification contract, and revocation protocol.

Haldir is the reference implementation.

## Security

- **Constant-time comparison** for all hash digests (`crypto.timingSafeEqual`)
- **Symlink rejection** across entire skill directory tree
- **Hard link rejection** on regular files (install context)
- **Size limits**: 10K files, 100MB per file, 500MB total
- **Schema version gates** on every parsed file
- **Clock skew tolerance** (300s) on all timestamp comparisons
- **Canonical JSON** (RFC 8785) eliminates serialization ambiguity
- **canonicalize** npm pinned to exact version with compatibility tests

To report a security vulnerability, please email security@haldir.ai.

## License

Apache 2.0
