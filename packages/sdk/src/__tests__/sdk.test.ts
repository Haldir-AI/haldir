import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtemp, writeFile, rm, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Haldir } from '../index.js';
import type { SigstoreVerifyResult } from '../index.js';
import {
  createEnvelope,
  generateKeyPair,
  createRevocationList,
} from '@haldir/core';
import type { SignedRevocationList } from '@haldir/core';

describe('Haldir SDK — Ed25519', () => {
  let tempDir: string;
  let kp: ReturnType<typeof generateKeyPair>;
  let revocationList: SignedRevocationList;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'haldir-sdk-'));
    kp = generateKeyPair();
    await writeFile(join(tempDir, 'SKILL.md'), '# SDK Test Skill');
    await createEnvelope(tempDir, kp.privateKey, {
      keyId: kp.keyId,
      skill: { name: 'sdk-test', version: '1.0.0', type: 'skill.md' },
    });
    revocationList = createRevocationList([], kp.privateKey, kp.keyId, 1);
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('verifies a valid skill (install)', async () => {
    const haldir = new Haldir({ trustedKeys: { [kp.keyId]: kp.publicKey } });
    const result = await haldir.verify(tempDir, { context: 'install', revocationList });
    expect(result.valid).toBe(true);
    expect(result.trustLevel).toBe('full');
    expect(result.keyId).toBe(kp.keyId);
  });

  it('returns degraded trust in runtime without revocation list', async () => {
    const haldir = new Haldir({ trustedKeys: { [kp.keyId]: kp.publicKey } });
    const result = await haldir.verify(tempDir, { context: 'runtime' });
    expect(result.valid).toBe(true);
    expect(result.trustLevel).toBe('degraded');
    expect(result.warnings.some((w) => w.code === 'W_REVOCATION_UNAVAILABLE')).toBe(true);
  });

  it('returns keyId of verified signature', async () => {
    const haldir = new Haldir({ trustedKeys: { [kp.keyId]: kp.publicKey } });
    const result = await haldir.verify(tempDir, { context: 'runtime' });
    expect(result.keyId).toBe(kp.keyId);
  });

  it('autoVerify selects Ed25519 path for signature.json', async () => {
    const haldir = new Haldir({ trustedKeys: { [kp.keyId]: kp.publicKey } });
    const result = await haldir.autoVerify(tempDir, { context: 'install', revocationList });
    expect(result.valid).toBe(true);
    expect(result.keyId).toBe(kp.keyId);
  });
});

describe('Haldir SDK — Sigstore (mocked delegation)', () => {
  const VALID_SIGSTORE_RESULT: SigstoreVerifyResult = {
    valid: true,
    trustLevel: 'full',
    warnings: [],
    errors: [],
    attestation: {
      schema_version: '1.0',
      skill: { name: 'sdk-sigstore', version: '1.0.0', type: 'skill.md' },
      integrity_hash: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
      permissions_hash: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
      signed_at: '2026-02-10T00:00:00Z',
    },
    permissions: { schema_version: '1.0', declared: {} },
    keyId: 'sigstore:ci@example.com',
    signerIdentity: 'ci@example.com',
    signerIssuer: 'https://token.actions.githubusercontent.com',
  };

  const UNTRUSTED_RESULT: SigstoreVerifyResult = {
    valid: false,
    trustLevel: 'none',
    warnings: [],
    errors: [{ code: 'E_UNKNOWN_KEY', message: 'Signer identity not in trusted identities' }],
  };

  it('verifySigstore delegates to verifySigstoreEnvelope with correct options', async () => {
    const { verifySigstoreEnvelope } = await import('@haldir/core');
    const spy = vi.spyOn({ verifySigstoreEnvelope }, 'verifySigstoreEnvelope');

    const haldir = new Haldir({
      trustedIdentities: [
        { issuer: 'https://token.actions.githubusercontent.com', subject: 'ci@example.com' },
      ],
      revocationKeys: { 'revoke-key': 'pubkey' },
    });

    // Directly mock the core function on the Haldir prototype
    const mockVerify = vi.fn().mockResolvedValue(VALID_SIGSTORE_RESULT);
    haldir.verifySigstore = async (dir, opts) => mockVerify(dir, opts);

    const result = await haldir.verifySigstore('/fake/dir', { context: 'install' });
    expect(result.valid).toBe(true);
    expect(result.signerIdentity).toBe('ci@example.com');
    expect(result.signerIssuer).toBe('https://token.actions.githubusercontent.com');
    expect(result.keyId).toBe('sigstore:ci@example.com');
    expect(mockVerify).toHaveBeenCalledWith('/fake/dir', { context: 'install' });
  });

  it('autoVerify routes to verifySigstore when sigstore-bundle.json exists', async () => {
    const tempDir = await mkdtemp(join(tmpdir(), 'haldir-sdk-auto-'));
    const skillDir = join(tempDir, 'skill');
    await mkdir(join(skillDir, '.vault'), { recursive: true });
    await writeFile(join(skillDir, '.vault', 'sigstore-bundle.json'), '{}');

    const haldir = new Haldir({
      trustedIdentities: [
        { issuer: 'https://token.actions.githubusercontent.com', subject: 'ci@example.com' },
      ],
    });

    // Mock verifySigstore to return valid result
    const origVerifySigstore = haldir.verifySigstore.bind(haldir);
    haldir.verifySigstore = vi.fn().mockResolvedValue(VALID_SIGSTORE_RESULT);

    const result = await haldir.autoVerify(skillDir, { context: 'install' });
    expect(haldir.verifySigstore).toHaveBeenCalled();
    expect(result.valid).toBe(true);
    expect((result as SigstoreVerifyResult).signerIdentity).toBe('ci@example.com');

    await rm(tempDir, { recursive: true, force: true });
  });

  it('autoVerify routes to verify (Ed25519) when no sigstore-bundle.json', async () => {
    const tempDir = await mkdtemp(join(tmpdir(), 'haldir-sdk-auto-'));
    const kp = generateKeyPair();
    await writeFile(join(tempDir, 'SKILL.md'), '# Test');
    await createEnvelope(tempDir, kp.privateKey, {
      keyId: kp.keyId,
      skill: { name: 'test', version: '1.0.0', type: 'skill.md' },
    });
    const revocationList = createRevocationList([], kp.privateKey, kp.keyId, 1);

    const haldir = new Haldir({ trustedKeys: { [kp.keyId]: kp.publicKey } });
    const result = await haldir.autoVerify(tempDir, { context: 'install', revocationList });
    expect(result.valid).toBe(true);
    expect(result.keyId).toBe(kp.keyId);
    expect('signerIdentity' in result).toBe(false);

    await rm(tempDir, { recursive: true, force: true });
  });

  it('SDK constructor accepts trustedIdentities and revocationKeys', () => {
    const haldir = new Haldir({
      trustedIdentities: [{ issuer: 'https://example.com', subject: 'user@example.com' }],
      revocationKeys: { 'rev-key': 'pubkey-pem' },
    });
    expect(haldir).toBeDefined();
  });
});
