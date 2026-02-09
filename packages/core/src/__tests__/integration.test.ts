import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { readFile, writeFile, rm, mkdtemp, cp, symlink, link } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import {
  generateKeyPair,
  createEnvelope,
  verifyEnvelope,
  createRevocationList,
  isRevoked,
} from '../index.js';
import type { VerifyOptions, SignedRevocationList } from '../types.js';

const FIXTURES = resolve(__dirname, '../../../../fixtures');

describe('integration: committed fixtures', () => {
  let publicKey: string;
  let privateKey: string;
  let keyId: string;
  let revocationList: SignedRevocationList;

  beforeEach(async () => {
    publicKey = await readFile(join(FIXTURES, 'keys/test.pub'), 'utf-8');
    privateKey = await readFile(join(FIXTURES, 'keys/test.key'), 'utf-8');
    keyId = (await readFile(join(FIXTURES, 'keys/test.keyid'), 'utf-8')).trim();
    revocationList = createRevocationList([], privateKey, keyId, 1);
  });

  it('verifies the committed valid skill fixture', async () => {
    const result = await verifyEnvelope(join(FIXTURES, 'skills/valid'), {
      trustedKeys: { [keyId]: publicKey },
      context: 'install',
      revocationList,
    });
    expect(result.valid).toBe(true);
    expect(result.trustLevel).toBe('full');
    expect(result.keyId).toBe(keyId);
    expect(result.attestation?.skill.name).toBe('quote-generator');
    expect(result.attestation?.skill.version).toBe('1.0.0');
  });

  it('rejects the unsigned skill fixture', async () => {
    const result = await verifyEnvelope(join(FIXTURES, 'skills/unsigned'), {
      trustedKeys: { [keyId]: publicKey },
      context: 'install',
      revocationList,
    });
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_NO_ENVELOPE');
  });

  it('rejects the valid fixture with wrong key', async () => {
    const wrongKp = generateKeyPair();
    const result = await verifyEnvelope(join(FIXTURES, 'skills/valid'), {
      trustedKeys: { [wrongKp.keyId]: wrongKp.publicKey },
      context: 'install',
      revocationList,
    });
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_UNKNOWN_KEY');
  });
});

describe('integration: end-to-end flow', () => {
  let tempDir: string;
  let kp: ReturnType<typeof generateKeyPair>;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'haldir-e2e-'));
    kp = generateKeyPair();
    await writeFile(join(tempDir, 'SKILL.md'), '# End-to-End Test Skill');
    await writeFile(join(tempDir, 'config.json'), '{"version": 1}');
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  function opts(overrides?: Partial<VerifyOptions>): VerifyOptions {
    return {
      trustedKeys: { [kp.keyId]: kp.publicKey },
      context: 'install',
      revocationList: createRevocationList([], kp.privateKey, kp.keyId, 1),
      ...overrides,
    };
  }

  it('keygen → sign → verify ✓ → tamper → verify ✗', async () => {
    // Sign
    await createEnvelope(tempDir, kp.privateKey, {
      keyId: kp.keyId,
      skill: { name: 'e2e-skill', version: '2.0.0', type: 'skill.md' },
    });

    // Verify passes
    const r1 = await verifyEnvelope(tempDir, opts());
    expect(r1.valid).toBe(true);
    expect(r1.trustLevel).toBe('full');
    expect(r1.attestation?.skill.name).toBe('e2e-skill');
    expect(r1.attestation?.skill.version).toBe('2.0.0');
    expect(r1.keyId).toBe(kp.keyId);

    // Tamper with file content
    await writeFile(join(tempDir, 'SKILL.md'), '# TAMPERED CONTENT');

    // Verify fails with integrity mismatch
    const r2 = await verifyEnvelope(tempDir, opts());
    expect(r2.valid).toBe(false);
    expect(r2.errors[0].code).toBe('E_INTEGRITY_MISMATCH');
  });

  it('sign → verify ✓ → add extra file → verify ✗', async () => {
    await createEnvelope(tempDir, kp.privateKey, {
      keyId: kp.keyId,
      skill: { name: 'e2e-skill', version: '1.0.0', type: 'skill.md' },
    });

    const r1 = await verifyEnvelope(tempDir, opts());
    expect(r1.valid).toBe(true);

    // Add undeclared file
    await writeFile(join(tempDir, 'extra.txt'), 'undeclared file');

    const r2 = await verifyEnvelope(tempDir, opts());
    expect(r2.valid).toBe(false);
    expect(r2.errors[0].code).toBe('E_EXTRA_FILES');
    expect(r2.errors[0].file).toBe('extra.txt');
  });

  it('sign → verify ✓ → revoke → verify ✗', async () => {
    await createEnvelope(tempDir, kp.privateKey, {
      keyId: kp.keyId,
      skill: { name: 'e2e-skill', version: '1.0.0', type: 'skill.md' },
    });

    // Verify passes with clean revocation list
    const cleanList = createRevocationList([], kp.privateKey, kp.keyId, 1);
    const r1 = await verifyEnvelope(tempDir, opts({ revocationList: cleanList }));
    expect(r1.valid).toBe(true);

    // Create revocation list that revokes this skill
    const revokedList = createRevocationList(
      [{
        name: 'e2e-skill',
        versions: ['1.0.0'],
        revoked_at: new Date().toISOString(),
        reason: 'security vulnerability',
        severity: 'critical',
      }],
      kp.privateKey,
      kp.keyId,
      2,
    );

    // Verify fails (install context, fail-closed)
    const r2 = await verifyEnvelope(tempDir, opts({ revocationList: revokedList }));
    expect(r2.valid).toBe(false);
    expect(r2.errors[0].code).toBe('E_REVOKED');

    // Runtime context also revokes immediately
    const r3 = await verifyEnvelope(tempDir, opts({
      context: 'runtime',
      revocationList: revokedList,
    }));
    expect(r3.valid).toBe(false);
    expect(r3.errors[0].code).toBe('E_REVOKED');
  });

  it('sign → verify ✓ → wildcard revoke → all versions blocked', async () => {
    await createEnvelope(tempDir, kp.privateKey, {
      keyId: kp.keyId,
      skill: { name: 'e2e-skill', version: '3.5.0', type: 'skill.md' },
    });

    const wildcardList = createRevocationList(
      [{
        name: 'e2e-skill',
        versions: ['*'],
        revoked_at: new Date().toISOString(),
        reason: 'publisher compromised',
        severity: 'critical',
      }],
      kp.privateKey,
      kp.keyId,
      1,
    );

    const r = await verifyEnvelope(tempDir, opts({ revocationList: wildcardList }));
    expect(r.valid).toBe(false);
    expect(r.errors[0].code).toBe('E_REVOKED');
  });

  it('sign → symlink injection → verify ✗', async () => {
    await createEnvelope(tempDir, kp.privateKey, {
      keyId: kp.keyId,
      skill: { name: 'e2e-skill', version: '1.0.0', type: 'skill.md' },
    });

    // Inject symlink
    await symlink('/etc/passwd', join(tempDir, 'malicious-link'));

    const r = await verifyEnvelope(tempDir, opts());
    expect(r.valid).toBe(false);
    expect(r.errors[0].code).toBe('E_SYMLINK');
  });

  it('sign → hard link injection → verify ✗', async () => {
    await createEnvelope(tempDir, kp.privateKey, {
      keyId: kp.keyId,
      skill: { name: 'e2e-skill', version: '1.0.0', type: 'skill.md' },
    });

    // Create hard link (nlink > 1)
    await link(join(tempDir, 'SKILL.md'), join(tempDir, 'hardcopy'));

    const r = await verifyEnvelope(tempDir, opts());
    expect(r.valid).toBe(false);
    // Hard link detected on SKILL.md (nlink=2) or extra file — either catches it
    const codes = r.errors.map(e => e.code);
    expect(codes.some(c => c === 'E_HARDLINK' || c === 'E_EXTRA_FILES')).toBe(true);
  });

  it('runtime degraded → no revocation list → still valid', async () => {
    await createEnvelope(tempDir, kp.privateKey, {
      keyId: kp.keyId,
      skill: { name: 'e2e-skill', version: '1.0.0', type: 'skill.md' },
    });

    const r = await verifyEnvelope(tempDir, opts({
      context: 'runtime',
      revocationList: undefined,
    }));
    expect(r.valid).toBe(true);
    expect(r.trustLevel).toBe('degraded');
    expect(r.warnings.some(w => w.code === 'W_REVOCATION_UNAVAILABLE')).toBe(true);
  });

  it('install → no revocation list → rejected', async () => {
    await createEnvelope(tempDir, kp.privateKey, {
      keyId: kp.keyId,
      skill: { name: 'e2e-skill', version: '1.0.0', type: 'skill.md' },
    });

    const r = await verifyEnvelope(tempDir, opts({
      context: 'install',
      revocationList: undefined,
    }));
    expect(r.valid).toBe(false);
    expect(r.errors[0].code).toBe('E_REVOCATION_STALE');
  });

  it('full lifecycle: sign → verify → tamper → re-sign → verify', async () => {
    // Sign and verify
    await createEnvelope(tempDir, kp.privateKey, {
      keyId: kp.keyId,
      skill: { name: 'e2e-skill', version: '1.0.0', type: 'skill.md' },
    });
    const r1 = await verifyEnvelope(tempDir, opts());
    expect(r1.valid).toBe(true);

    // Tamper
    await writeFile(join(tempDir, 'config.json'), '{"version": 2, "updated": true}');
    const r2 = await verifyEnvelope(tempDir, opts());
    expect(r2.valid).toBe(false);

    // Re-sign with updated content
    await createEnvelope(tempDir, kp.privateKey, {
      keyId: kp.keyId,
      skill: { name: 'e2e-skill', version: '1.1.0', type: 'skill.md' },
    });
    const r3 = await verifyEnvelope(tempDir, opts());
    expect(r3.valid).toBe(true);
    expect(r3.attestation?.skill.version).toBe('1.1.0');
  });
});
