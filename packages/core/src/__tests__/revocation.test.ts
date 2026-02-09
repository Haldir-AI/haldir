import { describe, it, expect } from 'vitest';
import {
  createRevocationList,
  verifyRevocationList,
  isRevoked,
  checkRevocationForInstall,
  checkRevocationForRuntime,
} from '../revocation.js';
import { generateKeyPair } from '../crypto.js';
import type { RevocationEntry, KeyRing } from '../types.js';

function makeEntry(name = 'bad-skill', versions = ['*']): RevocationEntry {
  return {
    name,
    versions,
    revoked_at: new Date().toISOString(),
    reason: 'test revocation',
    severity: 'critical',
  };
}

describe('createRevocationList + verifyRevocationList', () => {
  it('creates and verifies a list', () => {
    const kp = generateKeyPair();
    const list = createRevocationList([makeEntry()], kp.privateKey, kp.keyId, 1);
    const result = verifyRevocationList(list, { [kp.keyId]: kp.publicKey });
    expect(result.valid).toBe(true);
  });

  it('rejects list with wrong key', () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const list = createRevocationList([makeEntry()], kp1.privateKey, kp1.keyId, 1);
    const result = verifyRevocationList(list, { [kp1.keyId]: kp2.publicKey });
    expect(result.valid).toBe(false);
  });

  it('rejects list with unknown keyid', () => {
    const kp = generateKeyPair();
    const list = createRevocationList([makeEntry()], kp.privateKey, kp.keyId, 1);
    const result = verifyRevocationList(list, { 'other-key': kp.publicKey });
    expect(result.valid).toBe(false);
  });
});

describe('isRevoked', () => {
  it('matches exact version', () => {
    const kp = generateKeyPair();
    const list = createRevocationList(
      [makeEntry('my-skill', ['1.0.0'])],
      kp.privateKey,
      kp.keyId,
      1
    );
    expect(isRevoked('my-skill', '1.0.0', list)).toBe(true);
    expect(isRevoked('my-skill', '2.0.0', list)).toBe(false);
  });

  it('matches wildcard version', () => {
    const kp = generateKeyPair();
    const list = createRevocationList(
      [makeEntry('my-skill', ['*'])],
      kp.privateKey,
      kp.keyId,
      1
    );
    expect(isRevoked('my-skill', '999.0.0', list)).toBe(true);
  });

  it('does not match different name', () => {
    const kp = generateKeyPair();
    const list = createRevocationList(
      [makeEntry('other-skill', ['*'])],
      kp.privateKey,
      kp.keyId,
      1
    );
    expect(isRevoked('my-skill', '1.0.0', list)).toBe(false);
  });
});

describe('checkRevocationForInstall', () => {
  it('fails when no list provided', () => {
    const result = checkRevocationForInstall('skill', '1.0.0', undefined, {});
    expect(result.trustLevel).toBe('none');
    expect(result.errors[0].code).toBe('E_REVOCATION_STALE');
  });

  it('fails when list signature invalid', () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const list = createRevocationList([], kp1.privateKey, kp1.keyId, 1);
    const keys: KeyRing = { [kp1.keyId]: kp2.publicKey };
    const result = checkRevocationForInstall('skill', '1.0.0', list, keys);
    expect(result.trustLevel).toBe('none');
  });

  it('fails when expired', () => {
    const kp = generateKeyPair();
    const list = createRevocationList([], kp.privateKey, kp.keyId, 1, -1); // expired 1h ago
    const keys: KeyRing = { [kp.keyId]: kp.publicKey };
    const result = checkRevocationForInstall('skill', '1.0.0', list, keys);
    expect(result.trustLevel).toBe('none');
  });

  it('fails on sequence rollback', () => {
    const kp = generateKeyPair();
    const list = createRevocationList([], kp.privateKey, kp.keyId, 5);
    const keys: KeyRing = { [kp.keyId]: kp.publicKey };
    const result = checkRevocationForInstall('skill', '1.0.0', list, keys, 10);
    expect(result.trustLevel).toBe('none');
    expect(result.errors[0].code).toBe('E_REVOCATION_STALE');
  });

  it('fails when skill is revoked', () => {
    const kp = generateKeyPair();
    const list = createRevocationList(
      [makeEntry('skill', ['1.0.0'])],
      kp.privateKey,
      kp.keyId,
      1
    );
    const keys: KeyRing = { [kp.keyId]: kp.publicKey };
    const result = checkRevocationForInstall('skill', '1.0.0', list, keys);
    expect(result.trustLevel).toBe('none');
    expect(result.errors[0].code).toBe('E_REVOKED');
  });

  it('passes when skill not revoked', () => {
    const kp = generateKeyPair();
    const list = createRevocationList([], kp.privateKey, kp.keyId, 1);
    const keys: KeyRing = { [kp.keyId]: kp.publicKey };
    const result = checkRevocationForInstall('skill', '1.0.0', list, keys);
    expect(result.trustLevel).toBe('full');
    expect(result.newSequenceNumber).toBe(1);
  });
});

describe('checkRevocationForRuntime', () => {
  it('returns degraded when no list', () => {
    const result = checkRevocationForRuntime('skill', '1.0.0', undefined, {});
    expect(result.trustLevel).toBe('degraded');
    expect(result.warnings[0].code).toBe('W_REVOCATION_UNAVAILABLE');
  });

  it('returns degraded when signature invalid', () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const list = createRevocationList([], kp1.privateKey, kp1.keyId, 1);
    const keys: KeyRing = { [kp1.keyId]: kp2.publicKey };
    const result = checkRevocationForRuntime('skill', '1.0.0', list, keys);
    expect(result.trustLevel).toBe('degraded');
    expect(result.warnings[0].code).toBe('W_REVOCATION_SIG_INVALID');
  });

  it('returns degraded on stale sequence rollback', () => {
    const kp = generateKeyPair();
    const list = createRevocationList([], kp.privateKey, kp.keyId, 5);
    const keys: KeyRing = { [kp.keyId]: kp.publicKey };
    const result = checkRevocationForRuntime('skill', '1.0.0', list, keys, 10);
    expect(result.trustLevel).toBe('degraded');
  });

  it('immediately revokes at runtime', () => {
    const kp = generateKeyPair();
    const list = createRevocationList(
      [makeEntry('skill', ['*'])],
      kp.privateKey,
      kp.keyId,
      1
    );
    const keys: KeyRing = { [kp.keyId]: kp.publicKey };
    const result = checkRevocationForRuntime('skill', '1.0.0', list, keys);
    expect(result.trustLevel).toBe('none');
    expect(result.errors[0].code).toBe('E_REVOKED');
  });

  it('passes with valid list', () => {
    const kp = generateKeyPair();
    const list = createRevocationList([], kp.privateKey, kp.keyId, 1);
    const keys: KeyRing = { [kp.keyId]: kp.publicKey };
    const result = checkRevocationForRuntime('skill', '1.0.0', list, keys);
    expect(result.trustLevel).toBe('full');
    expect(result.newSequenceNumber).toBe(1);
  });

  // lastValidList fallback tests
  it('revokes via lastValidList when no current list', () => {
    const kp = generateKeyPair();
    const keys: KeyRing = { [kp.keyId]: kp.publicKey };
    const lastValid = createRevocationList(
      [makeEntry('skill', ['1.0.0'])],
      kp.privateKey,
      kp.keyId,
      1
    );
    const result = checkRevocationForRuntime('skill', '1.0.0', undefined, keys, undefined, lastValid);
    expect(result.trustLevel).toBe('none');
    expect(result.errors[0].code).toBe('E_REVOKED');
  });

  it('returns degraded when no list and lastValidList has no match', () => {
    const kp = generateKeyPair();
    const lastValid = createRevocationList([], kp.privateKey, kp.keyId, 1);
    const result = checkRevocationForRuntime('skill', '1.0.0', undefined, {}, undefined, lastValid);
    expect(result.trustLevel).toBe('degraded');
    expect(result.warnings[0].code).toBe('W_REVOCATION_UNAVAILABLE');
  });

  it('revokes via lastValidList when current list sig invalid', () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const list = createRevocationList([], kp1.privateKey, kp1.keyId, 1);
    const keys: KeyRing = { [kp1.keyId]: kp2.publicKey, [kp2.keyId]: kp2.publicKey };
    const lastValid = createRevocationList(
      [makeEntry('skill', ['*'])],
      kp2.privateKey,
      kp2.keyId,
      1
    );
    const result = checkRevocationForRuntime('skill', '1.0.0', list, keys, undefined, lastValid);
    expect(result.trustLevel).toBe('none');
    expect(result.errors[0].code).toBe('E_REVOKED');
  });

  it('revokes via lastValidList on sequence rollback', () => {
    const kp = generateKeyPair();
    const list = createRevocationList([], kp.privateKey, kp.keyId, 5);
    const keys: KeyRing = { [kp.keyId]: kp.publicKey };
    const lastValid = createRevocationList(
      [makeEntry('skill', ['1.0.0'])],
      kp.privateKey,
      kp.keyId,
      10
    );
    const result = checkRevocationForRuntime('skill', '1.0.0', list, keys, 10, lastValid);
    expect(result.trustLevel).toBe('none');
    expect(result.errors[0].code).toBe('E_REVOKED');
  });

  it('returns degraded on rollback when lastValidList has no match', () => {
    const kp = generateKeyPair();
    const list = createRevocationList([], kp.privateKey, kp.keyId, 5);
    const keys: KeyRing = { [kp.keyId]: kp.publicKey };
    const lastValid = createRevocationList([], kp.privateKey, kp.keyId, 10);
    const result = checkRevocationForRuntime('skill', '1.0.0', list, keys, 10, lastValid);
    expect(result.trustLevel).toBe('degraded');
  });

  it('ignores forged lastValidList (wrong key)', () => {
    const kp = generateKeyPair();
    const attacker = generateKeyPair();
    const forgedLastValid = createRevocationList(
      [makeEntry('skill', ['1.0.0'])],
      attacker.privateKey,
      attacker.keyId,
      1
    );
    const keys: KeyRing = { [kp.keyId]: kp.publicKey };
    const result = checkRevocationForRuntime('skill', '1.0.0', undefined, keys, undefined, forgedLastValid);
    expect(result.trustLevel).toBe('degraded');
    expect(result.warnings[0].code).toBe('W_REVOCATION_UNAVAILABLE');
    expect(result.errors).toHaveLength(0);
  });

  it('ignores forged lastValidList on sig-invalid fallback', () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const attacker = generateKeyPair();
    const list = createRevocationList([], kp1.privateKey, kp1.keyId, 1);
    const keys: KeyRing = { [kp1.keyId]: kp2.publicKey };
    const forgedLastValid = createRevocationList(
      [makeEntry('skill', ['*'])],
      attacker.privateKey,
      attacker.keyId,
      1
    );
    const result = checkRevocationForRuntime('skill', '1.0.0', list, keys, undefined, forgedLastValid);
    expect(result.trustLevel).toBe('degraded');
    expect(result.warnings[0].code).toBe('W_REVOCATION_SIG_INVALID');
    expect(result.errors).toHaveLength(0);
  });

  it('ignores expired lastValidList (stale beyond runtime grace)', () => {
    const kp = generateKeyPair();
    const keys: KeyRing = { [kp.keyId]: kp.publicKey };
    // Expired 48h ago — well beyond 24h runtime grace
    const staleLastValid = createRevocationList(
      [makeEntry('skill', ['1.0.0'])],
      kp.privateKey,
      kp.keyId,
      1,
      -48
    );
    const result = checkRevocationForRuntime('skill', '1.0.0', undefined, keys, undefined, staleLastValid);
    expect(result.trustLevel).toBe('degraded');
    expect(result.warnings[0].code).toBe('W_REVOCATION_UNAVAILABLE');
    expect(result.errors).toHaveLength(0);
  });
});
