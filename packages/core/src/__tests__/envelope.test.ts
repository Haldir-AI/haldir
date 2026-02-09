import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, readFile, rm, access } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createEnvelope } from '../envelope.js';
import { generateKeyPair, verify as ed25519Verify, base64urlDecode } from '../crypto.js';
import { encodePAE } from '../pae.js';
import { HALDIR_PAYLOAD_TYPE } from '../types.js';

let tempDir: string;

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), 'haldir-env-'));
  await writeFile(join(tempDir, 'SKILL.md'), '# Test Skill\nA test skill.');
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

describe('createEnvelope', () => {
  it('creates all 4 vault files', async () => {
    const kp = generateKeyPair();
    await createEnvelope(tempDir, kp.privateKey, {
      keyId: kp.keyId,
      skill: { name: 'test-skill', version: '1.0.0', type: 'skill.md' },
    });

    const vaultDir = join(tempDir, '.vault');
    await access(join(vaultDir, 'signature.json'));
    await access(join(vaultDir, 'attestation.json'));
    await access(join(vaultDir, 'integrity.json'));
    await access(join(vaultDir, 'permissions.json'));
  });

  it('writes attestation.json as canonical JSON (no whitespace)', async () => {
    const kp = generateKeyPair();
    await createEnvelope(tempDir, kp.privateKey, {
      keyId: kp.keyId,
      skill: { name: 'test', version: '1.0.0', type: 'skill.md' },
    });
    const raw = await readFile(join(tempDir, '.vault', 'attestation.json'), 'utf-8');
    expect(raw).not.toContain('\n');
    expect(raw).not.toContain('  ');
  });

  it('writes integrity.json as canonical JSON (no whitespace)', async () => {
    const kp = generateKeyPair();
    await createEnvelope(tempDir, kp.privateKey, {
      keyId: kp.keyId,
      skill: { name: 'test', version: '1.0.0', type: 'skill.md' },
    });
    const raw = await readFile(join(tempDir, '.vault', 'integrity.json'), 'utf-8');
    expect(raw).not.toContain('\n');
    expect(raw).not.toContain('  ');
  });

  it('writes signature.json as pretty-printed', async () => {
    const kp = generateKeyPair();
    await createEnvelope(tempDir, kp.privateKey, {
      keyId: kp.keyId,
      skill: { name: 'test', version: '1.0.0', type: 'skill.md' },
    });
    const raw = await readFile(join(tempDir, '.vault', 'signature.json'), 'utf-8');
    expect(raw).toContain('\n');
  });

  it('signature verifies against public key via PAE', async () => {
    const kp = generateKeyPair();
    await createEnvelope(tempDir, kp.privateKey, {
      keyId: kp.keyId,
      skill: { name: 'test', version: '1.0.0', type: 'skill.md' },
    });

    const sigRaw = JSON.parse(await readFile(join(tempDir, '.vault', 'signature.json'), 'utf-8'));
    const payloadBytes = base64urlDecode(sigRaw.payload);
    const pae = encodePAE(HALDIR_PAYLOAD_TYPE, payloadBytes);
    const sigBytes = base64urlDecode(sigRaw.signatures[0].sig);

    expect(ed25519Verify(pae, sigBytes, kp.publicKey)).toBe(true);
  });

  it('integrity hashes match sha256:<64hex> format', async () => {
    const kp = generateKeyPair();
    await createEnvelope(tempDir, kp.privateKey, {
      keyId: kp.keyId,
      skill: { name: 'test', version: '1.0.0', type: 'skill.md' },
    });

    const intRaw = JSON.parse(await readFile(join(tempDir, '.vault', 'integrity.json'), 'utf-8'));
    for (const hash of Object.values(intRaw.files)) {
      expect(hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    }
  });
});
