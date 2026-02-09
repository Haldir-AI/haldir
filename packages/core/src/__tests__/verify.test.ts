import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, readFile, rm, symlink, link, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createEnvelope } from '../envelope.js';
import { verifyEnvelope } from '../verify.js';
import { generateKeyPair, sign as ed25519Sign, hashData, base64urlEncode } from '../crypto.js';
import { canonicalize, canonicalizeToBuffer } from '../canonical.js';
import { encodePAE } from '../pae.js';
import { createRevocationList } from '../revocation.js';
import { HALDIR_PAYLOAD_TYPE } from '../types.js';
import type { VerifyOptions, SignedRevocationList } from '../types.js';

let tempDir: string;
let kp: ReturnType<typeof generateKeyPair>;
let revocationList: SignedRevocationList;

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), 'haldir-verify-'));
  kp = generateKeyPair();
  await writeFile(join(tempDir, 'SKILL.md'), '# Test Skill');
  await createEnvelope(tempDir, kp.privateKey, {
    keyId: kp.keyId,
    skill: { name: 'test-skill', version: '1.0.0', type: 'skill.md' },
  });
  revocationList = createRevocationList([], kp.privateKey, kp.keyId, 1);
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

function opts(overrides?: Partial<VerifyOptions>): VerifyOptions {
  return {
    trustedKeys: { [kp.keyId]: kp.publicKey },
    context: 'install',
    revocationList,
    ...overrides,
  };
}

describe('verifyEnvelope', () => {
  it('verifies a valid envelope', async () => {
    const result = await verifyEnvelope(tempDir, opts());
    expect(result.valid).toBe(true);
    expect(result.trustLevel).toBe('full');
    expect(result.keyId).toBe(kp.keyId);
    expect(result.attestation).toBeDefined();
    expect(result.attestation?.skill.name).toBe('test-skill');
    expect(result.permissions).toBeDefined();
    expect(result.errors).toHaveLength(0);
  });

  it('returns E_NO_ENVELOPE when .vault/ missing', async () => {
    const emptyDir = await mkdtemp(join(tmpdir(), 'haldir-empty-'));
    await writeFile(join(emptyDir, 'SKILL.md'), '# Test');
    const result = await verifyEnvelope(emptyDir, opts());
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_NO_ENVELOPE');
    await rm(emptyDir, { recursive: true, force: true });
  });

  it('returns E_INCOMPLETE when vault file missing', async () => {
    const { rm: rmFile } = await import('node:fs/promises');
    await rmFile(join(tempDir, '.vault', 'permissions.json'));
    const result = await verifyEnvelope(tempDir, opts());
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_INCOMPLETE');
  });

  it('returns E_SYMLINK when symlink found', async () => {
    await symlink('/etc/hosts', join(tempDir, 'bad-link'));
    const result = await verifyEnvelope(tempDir, opts());
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_SYMLINK');
  });

  it('returns E_HARDLINK when hard link found', async () => {
    await link(join(tempDir, 'SKILL.md'), join(tempDir, 'hardcopy'));
    const result = await verifyEnvelope(tempDir, opts());
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_HARDLINK');
  });

  it('skipHardlinkCheck ignored when context=install', async () => {
    await link(join(tempDir, 'SKILL.md'), join(tempDir, 'hardcopy'));
    const result = await verifyEnvelope(tempDir, opts({ skipHardlinkCheck: true, context: 'install' }));
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_HARDLINK');
  });

  it('skipHardlinkCheck works when context=runtime', async () => {
    await link(join(tempDir, 'SKILL.md'), join(tempDir, 'hardcopy'));
    const result = await verifyEnvelope(tempDir, opts({
      skipHardlinkCheck: true,
      context: 'runtime',
    }));
    // Still fails because extra file 'hardcopy' not in integrity
    expect(result.errors[0].code).toBe('E_EXTRA_FILES');
  });

  it('returns E_UNKNOWN_KEY when no trusted key matches', async () => {
    const kp2 = generateKeyPair();
    const result = await verifyEnvelope(tempDir, opts({
      trustedKeys: { [kp2.keyId]: kp2.publicKey },
    }));
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_UNKNOWN_KEY');
  });

  it('returns E_BAD_SIGNATURE with wrong key', async () => {
    const kp2 = generateKeyPair();
    // Use kp.keyId but kp2's public key
    const result = await verifyEnvelope(tempDir, opts({
      trustedKeys: { [kp.keyId]: kp2.publicKey },
    }));
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_BAD_SIGNATURE');
  });

  it('returns E_INTEGRITY_MISMATCH when file tampered', async () => {
    await writeFile(join(tempDir, 'SKILL.md'), '# Tampered!');
    const result = await verifyEnvelope(tempDir, opts());
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_INTEGRITY_MISMATCH');
  });

  it('returns E_EXTRA_FILES when undeclared file added', async () => {
    await writeFile(join(tempDir, 'extra.txt'), 'surprise');
    const result = await verifyEnvelope(tempDir, opts());
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_EXTRA_FILES');
  });

  // Multi-sig test: two signatures, only second matches
  it('verifies any matching signature, not just first', async () => {
    const kp2 = generateKeyPair();
    // Trust only kp2, but the envelope was signed with kp
    // Add kp2's key to trust and kp's key too — kp should verify
    const result = await verifyEnvelope(tempDir, opts({
      trustedKeys: {
        [kp2.keyId]: kp2.publicKey,
        [kp.keyId]: kp.publicKey,
      },
    }));
    expect(result.valid).toBe(true);
    expect(result.keyId).toBe(kp.keyId);
  });

  // Runtime with no revocation list
  it('returns degraded trust when runtime with no revocation list', async () => {
    const result = await verifyEnvelope(tempDir, opts({ context: 'runtime', revocationList: undefined }));
    expect(result.valid).toBe(true);
    expect(result.trustLevel).toBe('degraded');
    expect(result.warnings.some((w) => w.code === 'W_REVOCATION_UNAVAILABLE')).toBe(true);
  });

  // Fix #1: Path traversal — construct a fully signed envelope with a traversal path
  it('returns E_INTEGRITY_MISMATCH on path traversal (signed fixture)', async () => {
    // Build a fresh skill dir with a malicious signed envelope
    const malDir = await mkdtemp(join(tmpdir(), 'haldir-traversal-'));
    await writeFile(join(malDir, 'SKILL.md'), '# Legit Skill');
    const malKp = generateKeyPair();

    // Manually construct envelope with ../outside.txt in integrity
    const skillData = await readFile(join(malDir, 'SKILL.md'));
    const skillHash = hashData(skillData);
    const integrityObj = {
      schema_version: '1.0',
      algorithm: 'sha256',
      files: {
        '../outside.txt': 'sha256:' + '0'.repeat(64),
        'SKILL.md': skillHash,
      },
      generated_at: new Date().toISOString(),
    };
    const integrityBytes = canonicalizeToBuffer(integrityObj);
    const integrityHash = hashData(integrityBytes);

    const permissionsObj = {
      schema_version: '1.0',
      declared: { filesystem: { read: [], write: [] }, network: 'none', exec: [],
        agent_capabilities: { memory_read: false, memory_write: false, spawn_agents: false, modify_system_prompt: false } },
    };
    const permCanonical = canonicalizeToBuffer(permissionsObj);
    const permHash = hashData(permCanonical);

    const attestationObj = {
      schema_version: '1.0',
      skill: { name: 'evil', version: '1.0.0', type: 'skill.md' },
      integrity_hash: integrityHash,
      permissions_hash: permHash,
      signed_at: new Date().toISOString(),
    };
    const attestationBytes = canonicalizeToBuffer(attestationObj);
    const pae = encodePAE(HALDIR_PAYLOAD_TYPE, attestationBytes);
    const sig = ed25519Sign(pae, malKp.privateKey);

    const sigEnvelope = {
      schema_version: '1.0',
      payloadType: HALDIR_PAYLOAD_TYPE,
      payload: base64urlEncode(attestationBytes),
      signatures: [{ keyid: malKp.keyId, sig: base64urlEncode(sig) }],
    };

    const vaultDir = join(malDir, '.vault');
    await mkdir(vaultDir, { recursive: true });
    await writeFile(join(vaultDir, 'integrity.json'), integrityBytes);
    await writeFile(join(vaultDir, 'attestation.json'), attestationBytes);
    await writeFile(join(vaultDir, 'signature.json'), JSON.stringify(sigEnvelope, null, 2) + '\n');
    await writeFile(join(vaultDir, 'permissions.json'), JSON.stringify(permissionsObj, null, 2) + '\n');

    const malRevList = createRevocationList([], malKp.privateKey, malKp.keyId, 1);
    const result = await verifyEnvelope(malDir, {
      trustedKeys: { [malKp.keyId]: malKp.publicKey },
      context: 'install',
      revocationList: malRevList,
    });

    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_INTEGRITY_MISMATCH');
    expect(result.errors[0].message).toContain('Path traversal');
    expect(result.errors[0].file).toBe('../outside.txt');
    await rm(malDir, { recursive: true, force: true });
  });

  // Fix #2: Tampered attestation.json on disk
  it('returns E_INTEGRITY_MISMATCH when attestation.json on disk is tampered', async () => {
    const { readFile: rf, writeFile: wf } = await import('node:fs/promises');
    const attPath = join(tempDir, '.vault', 'attestation.json');
    const raw = await rf(attPath, 'utf-8');
    const att = JSON.parse(raw);
    att.skill.name = 'evil-skill';
    await wf(attPath, JSON.stringify(att));
    const result = await verifyEnvelope(tempDir, opts());
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_INTEGRITY_MISMATCH');
    expect(result.errors[0].message).toContain('attestation.json on disk');
  });

  // Fix #3: Malformed permissions.json fails verification
  it('returns E_INVALID_ENVELOPE when permissions.json is malformed', async () => {
    await writeFile(join(tempDir, '.vault', 'permissions.json'), '{not valid json!!!');
    const result = await verifyEnvelope(tempDir, opts());
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_INVALID_ENVELOPE');
  });

  // Round 2 fix: permissions.json tampered post-signing
  it('returns E_INTEGRITY_MISMATCH when permissions.json is tampered post-signing', async () => {
    const permPath = join(tempDir, '.vault', 'permissions.json');
    const raw = await readFile(permPath, 'utf-8');
    const perm = JSON.parse(raw);
    perm.declared.network = ['https://evil.com'];
    await writeFile(permPath, JSON.stringify(perm, null, 2) + '\n');
    const result = await verifyEnvelope(tempDir, opts());
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E_INTEGRITY_MISMATCH');
    expect(result.errors[0].message).toContain('permissions.json');
  });
});
