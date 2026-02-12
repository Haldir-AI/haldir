# End-to-End Test Suite

Comprehensive tests for Haldir's complete signing and verification workflow.

## Quick Start

```bash
# Run full e2e test suite
pnpm test:e2e

# Or use the CLI
node packages/cli/dist/index.js test
```

## Test Scenarios

### ✅ Happy Path Tests
- Sign valid skill → Verify passes
- Multi-file skills with various formats
- Skills with different permission sets
- Multi-signature verification (any match)

### 🔴 Security Tests
- Tamper detection (modified files)
- Extra file detection (files not in allowlist)
- Missing file detection (files removed)
- Symlink attack prevention
- Hard link attack prevention
- Path traversal prevention
- Size limit enforcement (10K files, 100MB/file, 500MB total)
- Invalid signature detection
- Expired signature detection
- Wrong public key detection

### 🔄 Revocation Tests
- Install context (fail-closed)
- Runtime context (fail-open with lastValidList)
- Revoked skill rejection
- Expired revocation list handling
- Forged revocation list rejection

### 📦 Real-World Tests
- Sign actual SKILL.md format
- Sign MCP server structure
- Sign multi-package skills
- Sign skills with binary files
- Cross-platform path handling

## Structure

```
e2e/
├── fixtures/           # Test skills and keys
│   ├── skills/
│   │   ├── simple/    # Minimal test skill
│   │   ├── complex/   # Multi-file skill
│   │   ├── mcp/       # MCP server format
│   │   └── skill-md/  # SKILL.md format
│   └── keys/          # Test keypairs
├── scenarios/         # Test scenario scripts
│   ├── happy-path.test.ts
│   ├── security.test.ts
│   ├── revocation.test.ts
│   └── real-world.test.ts
└── helpers/           # Test utilities
    ├── cli.ts         # CLI wrapper
    ├── assertions.ts  # Custom assertions
    └── fixtures.ts    # Fixture helpers
```

## Running Individual Scenarios

```bash
# Happy path only
pnpm vitest run e2e/scenarios/happy-path.test.ts

# Security tests only
pnpm vitest run e2e/scenarios/security.test.ts

# Real-world tests
pnpm vitest run e2e/scenarios/real-world.test.ts
```

## Writing New Tests

```typescript
import { runCLI, createTestSkill } from '../helpers';

test('my scenario', async () => {
  const skill = await createTestSkill({
    files: {
      'SKILL.md': '# My Skill',
      'skill.js': 'console.log("works");',
    },
  });

  const keypair = await runCLI('keygen');
  await runCLI('sign', skill.path, '--key', keypair.privateKey);
  const result = await runCLI('verify', skill.path, '--key', keypair.publicKey);

  expect(result.exitCode).toBe(0);
  expect(result.json.trustLevel).toBe('full');
});
```
