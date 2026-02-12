import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, readFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  generateKeyPair,
  createEnvelope,
  appendSignature,
  verifyEnvelope,
  createRevocationList,
} from '../index.js';
import type { SignedRevocationList, VerifyOptions } from '../index.js';

describe('Dual-sign (appendSignature + multi-sig verify)', () => {
  let tempDir: string;
  let publisherKeys: ReturnType<typeof generateKeyPair>;
  let authorityKeys: ReturnType<typeof generateKeyPair>;
  let revokeKeys: ReturnType<typeof generateKeyPair>;
  let revocationList: SignedRevocationList;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'haldir-dualsign-'));
    publisherKeys = generateKeyPair();
    authorityKeys = generateKeyPair();
    revokeKeys = generateKeyPair();
    // Revocation list signed by dedicated revocation key (realistic setup)
    revocationList = createRevocationList([], revokeKeys.privateKey, revokeKeys.keyId, 1);
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  async function createSignedSkill(skillDir: string) {
    await mkdir(skillDir, { recursive: true });
    await writeFile(join(skillDir, 'SKILL.md'), '# Test Skill\nDoes things.\n');

    await createEnvelope(skillDir, publisherKeys.privateKey, {
      keyId: publisherKeys.keyId,
      skill: { name: 'test-skill', version: '1.0.0', type: 'skill.md' },
    });
  }

  function publisherTrust(): Record<string, string> {
    return { [publisherKeys.keyId]: publisherKeys.publicKey };
  }

  // Always include the revocation key so revocation list verifies
  function verifyOpts(signerKeys: Record<string, string>): VerifyOptions {
    return {
      trustedKeys: {
        ...signerKeys,
        [revokeKeys.keyId]: revokeKeys.publicKey,
      },
      context: 'install',
      revocationList,
    };
  }

  it('appends a second signature to an existing envelope', async () => {
    const skillDir = join(tempDir, 'dual');
    await createSignedSkill(skillDir);

    await appendSignature(skillDir, authorityKeys.privateKey, undefined, {
      [publisherKeys.keyId]: publisherKeys.publicKey,
    });

    const sigRaw = await readFile(join(skillDir, '.vault', 'signature.json'), 'utf-8');
    const sig = JSON.parse(sigRaw);
    expect(sig.signatures).toHaveLength(2);
    expect(sig.signatures[0].keyid).toBe(publisherKeys.keyId);
    expect(sig.signatures[1].keyid).toBe(authorityKeys.keyId);
  });

  it('verifies with publisher key (first signature)', async () => {
    const skillDir = join(tempDir, 'verify-pub');
    await createSignedSkill(skillDir);
    await appendSignature(skillDir, authorityKeys.privateKey, undefined, publisherTrust());

    const result = await verifyEnvelope(skillDir, verifyOpts({
      [publisherKeys.keyId]: publisherKeys.publicKey,
    }));

    expect(result.valid).toBe(true);
    expect(result.keyId).toBe(publisherKeys.keyId);
  });

  it('verifies with authority key (second signature)', async () => {
    const skillDir = join(tempDir, 'verify-auth');
    await createSignedSkill(skillDir);
    await appendSignature(skillDir, authorityKeys.privateKey, undefined, publisherTrust());

    const result = await verifyEnvelope(skillDir, verifyOpts({
      [authorityKeys.keyId]: authorityKeys.publicKey,
    }));

    expect(result.valid).toBe(true);
    expect(result.keyId).toBe(authorityKeys.keyId);
  });

  it('verifies when both keys are trusted (returns first match)', async () => {
    const skillDir = join(tempDir, 'verify-both');
    await createSignedSkill(skillDir);
    await appendSignature(skillDir, authorityKeys.privateKey, undefined, publisherTrust());

    const result = await verifyEnvelope(skillDir, verifyOpts({
      [publisherKeys.keyId]: publisherKeys.publicKey,
      [authorityKeys.keyId]: authorityKeys.publicKey,
    }));

    expect(result.valid).toBe(true);
    // First matching signature wins
    expect(result.keyId).toBe(publisherKeys.keyId);
  });

  it('fails when neither signer key is trusted', async () => {
    const skillDir = join(tempDir, 'verify-none');
    await createSignedSkill(skillDir);
    await appendSignature(skillDir, authorityKeys.privateKey, undefined, publisherTrust());

    const unknownKeys = generateKeyPair();
    const result = await verifyEnvelope(skillDir, verifyOpts({
      [unknownKeys.keyId]: unknownKeys.publicKey,
    }));

    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_UNKNOWN_KEY');
  });

  it('rejects duplicate keyId in appendSignature', async () => {
    const skillDir = join(tempDir, 'dup');
    await createSignedSkill(skillDir);

    await expect(
      appendSignature(skillDir, publisherKeys.privateKey, undefined, publisherTrust())
    ).rejects.toThrow('already has a signature');
  });

  it('rejects if signature.json is missing', async () => {
    const skillDir = join(tempDir, 'nosig');
    await mkdir(skillDir, { recursive: true });
    await writeFile(join(skillDir, 'SKILL.md'), '# Test\n');
    await mkdir(join(skillDir, '.vault'), { recursive: true });

    await expect(
      appendSignature(skillDir, authorityKeys.privateKey, undefined, publisherTrust())
    ).rejects.toThrow();
  });

  it('supports 3+ co-signers', async () => {
    const skillDir = join(tempDir, 'triple');
    await createSignedSkill(skillDir);

    const secondSigner = generateKeyPair();
    const thirdSigner = generateKeyPair();

    await appendSignature(skillDir, authorityKeys.privateKey, undefined, publisherTrust());
    await appendSignature(skillDir, secondSigner.privateKey, undefined, publisherTrust());
    await appendSignature(skillDir, thirdSigner.privateKey, undefined, publisherTrust());

    const sigRaw = await readFile(join(skillDir, '.vault', 'signature.json'), 'utf-8');
    const sig = JSON.parse(sigRaw);
    expect(sig.signatures).toHaveLength(4);

    // Verify with third signer's key only
    const result = await verifyEnvelope(skillDir, verifyOpts({
      [thirdSigner.keyId]: thirdSigner.publicKey,
    }));
    expect(result.valid).toBe(true);
    expect(result.keyId).toBe(thirdSigner.keyId);
  });

  it('detects tampering after co-sign (integrity still holds)', async () => {
    const skillDir = join(tempDir, 'tamper');
    await createSignedSkill(skillDir);
    await appendSignature(skillDir, authorityKeys.privateKey, undefined, publisherTrust());

    // Tamper with the file
    await writeFile(join(skillDir, 'SKILL.md'), '# HACKED\n');

    const result = await verifyEnvelope(skillDir, verifyOpts({
      [authorityKeys.keyId]: authorityKeys.publicKey,
    }));

    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_INTEGRITY_MISMATCH');
  });
});
