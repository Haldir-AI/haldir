# Testing Haldir

Comprehensive testing guide for Haldir's cryptographic signing and verification.

## Quick Start

```bash
# Run built-in CLI test suite (recommended for quick validation)
pnpm build
pnpm test:cli

# Run full e2e test suite (comprehensive)
pnpm test:e2e

# Run unit tests (crypto, envelope, verification)
pnpm test

# Run everything
pnpm build && pnpm test && pnpm test:e2e && pnpm test:cli
```

## Test Suites

### 1. CLI Test Suite (`haldir test`)

**Purpose:** Quick validation that Haldir works end-to-end

**Tests:**
- ✓ Generate keypair
- ✓ Sign valid skill
- ✓ Verify valid signature
- ✓ Detect modified file (hash mismatch)
- ✓ Detect extra file (not in allowlist)
- ✓ Reject wrong public key
- ✓ Revocation enforcement

**Run:**
```bash
pnpm build
node packages/cli/dist/index.js test

# Or via script
pnpm test:cli
```

**Output:**
```
🧪 Haldir End-to-End Test Suite

✓ Generate keypair (45ms)
✓ Sign valid skill (123ms)
✓ Verify valid signature (89ms)
✓ Detect modified file (78ms)
✓ Detect extra file (81ms)
✓ Reject wrong public key (156ms)
✓ Revocation enforcement (201ms)

============================================================

📊 Test Results

Total:    7
Passed:   7 ✓
Failed:   0 ✗
Duration: 773ms

✅ All tests passed!
```

### 2. E2E Test Suite (`pnpm test:e2e`)

**Purpose:** Comprehensive validation of all scenarios

**Test Files:**
- `e2e/scenarios/happy-path.test.ts` - Valid signing/verification flows
- `e2e/scenarios/security.test.ts` - Tamper detection, attack prevention
- `e2e/scenarios/revocation.test.ts` - Revocation list enforcement

**Tests:** 25+ comprehensive scenarios

**Run:**
```bash
pnpm test:e2e

# Or run specific scenario
npx vitest run e2e/scenarios/happy-path.test.ts
npx vitest run e2e/scenarios/security.test.ts
npx vitest run e2e/scenarios/revocation.test.ts
```

### 3. Unit Tests (`pnpm test`)

**Purpose:** Low-level verification of crypto, canonicalization, schemas, vetting, enforcement

**Packages tested (11):**
- `@haldir/core` — crypto, canonical JSON, PAE, envelope, integrity, revocation, verification
- `@haldir/sdk` — Ed25519 + Sigstore verification
- `@haldir/scanner` — threat patterns, static analysis, serialization, context-aware scanning
- `@haldir/auditor` — dependency parsing, pin validation, CVE checks
- `@haldir/sandbox` — permissions, execution, behavior analysis
- `@haldir/reviewer` — dual-LLM prompts, scoring, escalation
- `@haldir/pipeline` — 5-layer orchestration
- `@haldir/enforcer` — permission compilation, Node.js + macOS sandbox
- `@haldir/registry` — store, server, tiers, auth, pattern bundles
- `@haldir/scheduler` — rescan policies, scheduling
- `@haldir/cli` — cache, registry client, pattern resolution

**Tests:** 687 across 44 test files

**Run:**
```bash
pnpm test

# Or with watch mode
pnpm test:watch
```

## Manual Testing

### Test Scenario 1: Sign and Verify a Simple Skill

```bash
# Build Haldir
pnpm build

# Create a test skill
mkdir -p /tmp/test-skill
cat > /tmp/test-skill/SKILL.md <<'EOF'
# Hello World Skill

A simple test skill.

## Permissions
None required.
EOF

cat > /tmp/test-skill/skill.js <<'EOF'
#!/usr/bin/env node
console.log("Hello, World!");
EOF

# Generate keypair
node packages/cli/dist/index.js keygen

# Sign the skill
node packages/cli/dist/index.js sign /tmp/test-skill --key haldir.key

# Verify the skill
node packages/cli/dist/index.js verify /tmp/test-skill \
  --key haldir.pub \
  --context install

# Expected output: trustLevel: "full", checks: { passed: 25+ }
```

### Test Scenario 2: Detect Tampering

```bash
# Using the signed skill from above

# Tamper: modify a file
echo "// tampered" >> /tmp/test-skill/skill.js

# Verify again (should fail)
node packages/cli/dist/index.js verify /tmp/test-skill \
  --key haldir.pub \
  --context install

# Expected output: error.code: "E_INTEGRITY_MISMATCH", trustLevel: "none"
```

### Test Scenario 3: Detect Extra Files

```bash
# Using a freshly signed skill

# Tamper: add extra file
echo "console.log('backdoor');" > /tmp/test-skill/backdoor.js

# Verify (should fail)
node packages/cli/dist/index.js verify /tmp/test-skill \
  --key haldir.pub \
  --context install

# Expected output: error.code: "E_EXTRA_FILES", trustLevel: "none"
```

### Test Scenario 4: Revocation

```bash
# Sign a skill
mkdir -p /tmp/revoked-skill
echo "# Test" > /tmp/revoked-skill/SKILL.md
node packages/cli/dist/index.js sign /tmp/revoked-skill --key haldir.key

# Create revocation list
node packages/cli/dist/index.js revoke test-skill@1.0.0 \
  --key haldir.key \
  --reason "Security vulnerability found" \
  --list revocations.json

# Verify with revocation list (should fail)
node packages/cli/dist/index.js verify /tmp/revoked-skill \
  --key haldir.pub \
  --context install \
  --revocation revocations.json

# Expected output: error.code: "E_REVOKED", trustLevel: "none"
```

## Test Fixtures

Pre-built test fixtures are available in `fixtures/`:

- `fixtures/keys/` - Test keypairs (NOT for production!)
- `fixtures/skills/valid/` - Signed skill with valid `.vault/`
- `fixtures/skills/unsigned/` - Unsigned skill (no `.vault/`)

## CI Testing

The CI workflow (`.github/workflows/ci.yml`) runs:

1. `pnpm install --frozen-lockfile`
2. `pnpm build`
3. `pnpm lint`
4. `pnpm test` (unit tests)
5. `pnpm schemas` (validate schema sync)

Tested on Node 20 and 22.

## Writing Custom Tests

### E2E Test Example

```typescript
import { test, expect } from "vitest";
import { createTestSkill } from "../helpers/fixtures";
import { generateKeypair, signSkill, verifySkill } from "../helpers/cli";

test("my custom scenario", async () => {
  const skill = await createTestSkill({
    files: {
      "SKILL.md": "# My Skill",
      "script.js": "console.log('works');",
    },
  });

  const keypair = await generateKeypair("/tmp");

  await signSkill(skill.path, keypair.privateKey);

  const result = await verifySkill(skill.path, keypair.publicKey, {
    context: "install",
  });

  expect(result.exitCode).toBe(0);
  expect(result.json.trustLevel).toBe("full");

  await skill.cleanup();
});
```

### Unit Test Example

```typescript
import { test, expect } from "vitest";
import { generateKeyPair, sign, verify } from "@haldir/core";

test("Ed25519 sign/verify", async () => {
  const keypair = await generateKeyPair();
  const message = Buffer.from("test message");

  const signature = await sign(message, keypair.privateKey);
  const valid = await verify(message, signature, keypair.publicKey);

  expect(valid).toBe(true);
});
```

## Test Coverage

Current coverage:

- **687 tests passing** across 44 test files, 11 packages
  - Core crypto & verification (149+ tests)
  - Vetting pipeline — scanner, auditor, sandbox, reviewer, pipeline (300+ tests)
  - Runtime enforcer (12+ tests)
  - Registry API — store, server, tiers, auth, patterns (80+ tests)
  - Scheduler — rescan policies (28+ tests)
  - SDK & CLI — verification, cache, registry client (50+ tests)
  - Integration & E2E (70+ tests)
- **CLI test suite:** 7 built-in tests

## Troubleshooting

### Tests fail with "Cannot find module"

Build first:
```bash
pnpm build
```

### E2E tests fail with ENOENT

Install dependencies:
```bash
pnpm install
```

### CLI test suite fails

Ensure packages are built:
```bash
pnpm build
pnpm test:cli
```

### "Network error" during pnpm install

Temporary DNS issue. Retry:
```bash
pnpm install --no-frozen-lockfile
```

## Performance Benchmarks

Expected test durations:

- **CLI test suite:** ~1 second (7 tests)
- **Unit tests:** ~2 seconds (687 tests)
- **E2E tests:** ~10 seconds (25+ tests)
- **Full suite:** ~13 seconds total

## Next Steps

1. **Local validation:** Run `pnpm test:cli` to verify your environment
2. **Full validation:** Run `pnpm test:e2e` for comprehensive testing
3. **Manual testing:** Follow scenarios in this guide
4. **CI validation:** Push to GitHub and verify CI passes

For more details, see:
- `e2e/README.md` - E2E test documentation
- `.github/workflows/ci.yml` - CI configuration
- `packages/core/src/__tests__/` - Unit test source code
