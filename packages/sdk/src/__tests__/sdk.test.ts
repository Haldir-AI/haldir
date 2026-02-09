import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Haldir } from '../index.js';
import { createEnvelope, generateKeyPair, createRevocationList } from '@haldir/core';
import type { SignedRevocationList } from '@haldir/core';

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

describe('Haldir SDK', () => {
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
});
