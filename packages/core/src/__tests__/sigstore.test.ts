import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, mkdir, rm, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  createEnvelope,
  createKeylessEnvelope,
  verifySigstoreEnvelope,
  generateKeyPair,
  hasSigstoreBundle,
  readSigstoreBundle,
  writeSigstoreBundle,
  SIGSTORE_BUNDLE_FILE,
} from '../index.js';
import type { Bundle } from 'sigstore';

// Mock the sigstore npm package (network-dependent)
vi.mock('sigstore', () => ({
  sign: vi.fn().mockResolvedValue({
    mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
    verificationMaterial: {
      timestampVerificationData: { rfc3161Timestamps: [] },
      tlogEntries: [{ logIndex: '12345', logId: { keyId: 'fakeid' } }],
    },
    content: {
      messageSignature: { messageDigest: { algorithm: 'SHA2_256', digest: 'abc' }, signature: 'sig' },
    },
  }),
  verify: vi.fn().mockResolvedValue({
    key: {},
    identity: {
      subjectAlternativeName: 'user@example.com',
      extensions: { issuer: 'https://accounts.google.com' },
    },
  }),
}));

const FAKE_BUNDLE: Bundle = {
  mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
  verificationMaterial: {
    timestampVerificationData: { rfc3161Timestamps: [] },
    tlogEntries: [{ logIndex: '12345', logId: { keyId: 'fakeid' } }],
  },
  content: {
    messageSignature: { messageDigest: { algorithm: 'SHA2_256', digest: 'abc' }, signature: 'sig' },
  },
} as unknown as Bundle;

describe('Sigstore helpers', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'haldir-sigstore-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  describe('hasSigstoreBundle', () => {
    it('returns false when no .vault/ exists', async () => {
      const skillDir = join(tempDir, 'skill');
      await mkdir(skillDir);
      expect(await hasSigstoreBundle(skillDir)).toBe(false);
    });

    it('returns false when .vault/ exists but no bundle', async () => {
      const skillDir = join(tempDir, 'skill');
      await mkdir(join(skillDir, '.vault'), { recursive: true });
      expect(await hasSigstoreBundle(skillDir)).toBe(false);
    });

    it('returns true when sigstore-bundle.json exists', async () => {
      const skillDir = join(tempDir, 'skill');
      await mkdir(join(skillDir, '.vault'), { recursive: true });
      await writeFile(join(skillDir, '.vault', SIGSTORE_BUNDLE_FILE), '{}');
      expect(await hasSigstoreBundle(skillDir)).toBe(true);
    });
  });

  describe('readSigstoreBundle / writeSigstoreBundle', () => {
    it('round-trips a bundle through write/read', async () => {
      const skillDir = join(tempDir, 'skill');
      await mkdir(join(skillDir, '.vault'), { recursive: true });

      await writeSigstoreBundle(skillDir, FAKE_BUNDLE);
      const read = await readSigstoreBundle(skillDir);
      expect(read).not.toBeNull();
      expect(read!.mediaType).toBe(FAKE_BUNDLE.mediaType);
    });

    it('readSigstoreBundle returns null when file missing', async () => {
      const skillDir = join(tempDir, 'skill');
      await mkdir(skillDir);
      expect(await readSigstoreBundle(skillDir)).toBeNull();
    });
  });
});

describe('createKeylessEnvelope', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'haldir-keyless-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('creates .vault/ with sigstore-bundle.json, attestation.json, integrity.json, permissions.json', async () => {
    const skillDir = join(tempDir, 'skill');
    await mkdir(skillDir);
    await writeFile(join(skillDir, 'SKILL.md'), '# Test Skill\n');

    await createKeylessEnvelope(skillDir, {
      skill: { name: 'test-keyless', version: '1.0.0', type: 'skill.md' },
      identityToken: 'fake-token',
    });

    const vaultDir = join(skillDir, '.vault');
    const bundle = await readFile(join(vaultDir, SIGSTORE_BUNDLE_FILE), 'utf-8');
    expect(JSON.parse(bundle)).toBeDefined();

    const attestation = await readFile(join(vaultDir, 'attestation.json'), 'utf-8');
    const att = JSON.parse(attestation);
    expect(att.skill.name).toBe('test-keyless');
    expect(att.skill.version).toBe('1.0.0');

    const integrity = await readFile(join(vaultDir, 'integrity.json'), 'utf-8');
    const integ = JSON.parse(integrity);
    expect(integ.files).toHaveProperty('SKILL.md');

    const permissions = await readFile(join(vaultDir, 'permissions.json'), 'utf-8');
    const perm = JSON.parse(permissions);
    expect(perm.schema_version).toBe('1.0');
  });

  it('does not create signature.json (keyless has no Ed25519 signature)', async () => {
    const skillDir = join(tempDir, 'skill');
    await mkdir(skillDir);
    await writeFile(join(skillDir, 'SKILL.md'), '# Test\n');

    await createKeylessEnvelope(skillDir, {
      skill: { name: 'test', version: '1.0.0', type: 'skill.md' },
    });

    await expect(readFile(join(skillDir, '.vault', 'signature.json'))).rejects.toThrow();
  });
});

const MOCK_TRUSTED_IDENTITIES = [
  { issuer: 'https://accounts.google.com', subject: 'user@example.com' },
];

describe('verifySigstoreEnvelope', () => {
  let tempDir: string;
  let keyPair: { publicKey: string; privateKey: string };

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'haldir-sigverify-'));
    keyPair = generateKeyPair();
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  async function setupKeylessSkill(skillDir: string, content = '# Test Skill\n') {
    await mkdir(skillDir, { recursive: true });
    await writeFile(join(skillDir, 'SKILL.md'), content);

    // Use createKeylessEnvelope which calls mocked signWithSigstore
    await createKeylessEnvelope(skillDir, {
      skill: { name: 'test-skill', version: '1.0.0', type: 'skill.md' },
      identityToken: 'fake-oidc-token',
    });
  }

  it('verifies a valid keyless-signed skill', async () => {
    const skillDir = join(tempDir, 'valid');
    await setupKeylessSkill(skillDir);

    const result = await verifySigstoreEnvelope(skillDir, {
      context: 'runtime',
      trustedIdentities: MOCK_TRUSTED_IDENTITIES,
    });

    expect(result.valid).toBe(true);
    expect(result.trustLevel).toBe('degraded'); // no revocation list → degraded at runtime
    expect(result.signerIdentity).toBe('user@example.com');
    expect(result.signerIssuer).toBe('https://accounts.google.com');
    expect(result.errors).toHaveLength(0);
  });

  it('returns keyId in sigstore:<identity> format', async () => {
    const skillDir = join(tempDir, 'keyid');
    await setupKeylessSkill(skillDir);

    const result = await verifySigstoreEnvelope(skillDir, { context: 'runtime', trustedIdentities: MOCK_TRUSTED_IDENTITIES });
    expect(result.keyId).toBe('sigstore:user@example.com');
  });

  it('validates trusted identities when provided', async () => {
    const skillDir = join(tempDir, 'trusted');
    await setupKeylessSkill(skillDir);

    const result = await verifySigstoreEnvelope(skillDir, {
      context: 'runtime',
      trustedIdentities: [
        { issuer: 'https://accounts.google.com', subject: 'user@example.com' },
      ],
    });

    expect(result.valid).toBe(true);
    expect(result.trustLevel).toBe('degraded'); // no revocation list → degraded at runtime
  });

  it('rejects untrusted signer identity', async () => {
    const skillDir = join(tempDir, 'untrusted');
    await setupKeylessSkill(skillDir);

    const result = await verifySigstoreEnvelope(skillDir, {
      context: 'install',
      trustedIdentities: [
        { issuer: 'https://token.actions.githubusercontent.com', subject: 'https://github.com/some/repo' },
      ],
    });

    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_UNKNOWN_KEY');
    expect(result.errors[0].message).toContain('not in trusted identities');
  });

  it('fails when .vault/ is missing', async () => {
    const skillDir = join(tempDir, 'novault');
    await mkdir(skillDir);
    await writeFile(join(skillDir, 'SKILL.md'), '# Test\n');

    const result = await verifySigstoreEnvelope(skillDir, { context: 'install', trustedIdentities: MOCK_TRUSTED_IDENTITIES });
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_NO_ENVELOPE');
  });

  it('fails when sigstore-bundle.json is missing', async () => {
    const skillDir = join(tempDir, 'nobundle');
    await mkdir(skillDir);
    await writeFile(join(skillDir, 'SKILL.md'), '# Test\n');

    // Use Ed25519 signing (creates signature.json, not sigstore-bundle.json)
    await createEnvelope(skillDir, keyPair.privateKey, {
      keyId: 'test-key',
      skill: { name: 'test', version: '1.0.0', type: 'skill.md' },
    });

    const result = await verifySigstoreEnvelope(skillDir, { context: 'install', trustedIdentities: MOCK_TRUSTED_IDENTITIES });
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_INCOMPLETE');
    expect(result.errors[0].message).toContain('sigstore-bundle.json');
  });

  it('fails when Sigstore verification throws', async () => {
    const skillDir = join(tempDir, 'badbundle');
    await setupKeylessSkill(skillDir);

    // Make verifyWithSigstore throw on next call
    const sigstore = await import('sigstore');
    (sigstore.verify as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error('certificate has expired')
    );

    const result = await verifySigstoreEnvelope(skillDir, { context: 'install', trustedIdentities: MOCK_TRUSTED_IDENTITIES });
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_BAD_SIGNATURE');
    expect(result.errors[0].message).toContain('certificate has expired');
  });

  it('rejects when trustedIdentities is not provided', async () => {
    const skillDir = join(tempDir, 'no-identity');
    await setupKeylessSkill(skillDir);

    const result = await verifySigstoreEnvelope(skillDir, { context: 'runtime' });
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_UNKNOWN_KEY');
    expect(result.errors[0].message).toContain('requires at least one trusted identity');
  });

  it('detects tampered file (integrity mismatch)', async () => {
    const skillDir = join(tempDir, 'tampered');
    await setupKeylessSkill(skillDir);

    await writeFile(join(skillDir, 'SKILL.md'), '# TAMPERED!\n');

    const result = await verifySigstoreEnvelope(skillDir, { context: 'install', trustedIdentities: MOCK_TRUSTED_IDENTITIES });
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_INTEGRITY_MISMATCH');
  });

  it('detects extra files', async () => {
    const skillDir = join(tempDir, 'extra');
    await setupKeylessSkill(skillDir);

    await writeFile(join(skillDir, 'malware.sh'), '#!/bin/bash\nrm -rf /\n');

    const result = await verifySigstoreEnvelope(skillDir, { context: 'install', trustedIdentities: MOCK_TRUSTED_IDENTITIES });
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_EXTRA_FILES');
  });

  it('rejects install without revocation list (fail-closed)', async () => {
    const skillDir = join(tempDir, 'norevoke-install');
    await setupKeylessSkill(skillDir);

    const result = await verifySigstoreEnvelope(skillDir, { context: 'install', trustedIdentities: MOCK_TRUSTED_IDENTITIES });
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_REVOCATION_STALE');
  });

  it('returns degraded trust for runtime without revocation list', async () => {
    const skillDir = join(tempDir, 'norevoke');
    await setupKeylessSkill(skillDir);

    const result = await verifySigstoreEnvelope(skillDir, { context: 'runtime', trustedIdentities: MOCK_TRUSTED_IDENTITIES });
    expect(result.valid).toBe(true);
    expect(result.trustLevel).toBe('degraded');
    expect(result.warnings[0].code).toBe('W_REVOCATION_UNAVAILABLE');
  });

  it('returns attestation and permissions on success', async () => {
    const skillDir = join(tempDir, 'meta');
    await setupKeylessSkill(skillDir);

    const result = await verifySigstoreEnvelope(skillDir, { context: 'runtime', trustedIdentities: MOCK_TRUSTED_IDENTITIES });
    expect(result.valid).toBe(true);
    expect(result.attestation).toBeDefined();
    expect(result.attestation!.skill.name).toBe('test-skill');
    expect(result.permissions).toBeDefined();
    expect(result.permissions!.schema_version).toBe('1.0');
  });
});
