# Test Keys

**⚠️ THESE ARE TEST KEYS ONLY - NOT FOR PRODUCTION USE**

This directory contains Ed25519 keypairs used exclusively for the Haldir test suite.

- `test.key` — Test private key (committed intentionally for testing)
- `test.pub` — Test public key
- `test.keyid` — Derived key identifier

**Security Note:**
- These keys are committed to git intentionally for reproducible tests
- They have NO cryptographic value outside the test suite
- NEVER use these keys to sign production skills
- Generate production keys with: `haldir keygen`

GitGuardian alerts for these files can be safely ignored - they are test fixtures, not leaked secrets.
