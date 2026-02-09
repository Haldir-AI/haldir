import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  deriveKeyId,
  sign,
  verify,
  hashData,
  safeHashCompare,
  parseHashString,
  base64urlEncode,
  base64urlDecode,
} from '../crypto.js';

describe('generateKeyPair', () => {
  it('returns PEM keys and keyId', () => {
    const kp = generateKeyPair();
    expect(kp.publicKey).toContain('BEGIN PUBLIC KEY');
    expect(kp.privateKey).toContain('BEGIN PRIVATE KEY');
    expect(kp.keyId).toHaveLength(32);
  });

  it('generates different keys each time', () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    expect(kp1.publicKey).not.toBe(kp2.publicKey);
    expect(kp1.keyId).not.toBe(kp2.keyId);
  });
});

describe('deriveKeyId', () => {
  it('returns deterministic 32-char hex (128-bit)', () => {
    const kp = generateKeyPair();
    const id1 = deriveKeyId(kp.publicKey);
    const id2 = deriveKeyId(kp.publicKey);
    expect(id1).toBe(id2);
    expect(id1).toHaveLength(32);
    expect(id1).toMatch(/^[0-9a-f]{32}$/);
  });
});

describe('sign + verify', () => {
  it('round-trips correctly', () => {
    const kp = generateKeyPair();
    const data = Buffer.from('test data');
    const sig = sign(data, kp.privateKey);
    expect(sig).toHaveLength(64);
    expect(verify(data, sig, kp.publicKey)).toBe(true);
  });

  it('rejects wrong key', () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const data = Buffer.from('test data');
    const sig = sign(data, kp1.privateKey);
    expect(verify(data, sig, kp2.publicKey)).toBe(false);
  });

  it('rejects tampered data', () => {
    const kp = generateKeyPair();
    const data = Buffer.from('test data');
    const sig = sign(data, kp.privateKey);
    const tampered = Buffer.from('test datb');
    expect(verify(tampered, sig, kp.publicKey)).toBe(false);
  });

  it('same key+message produces same signature', () => {
    const kp = generateKeyPair();
    const data = Buffer.from('deterministic');
    const sig1 = sign(data, kp.privateKey);
    const sig2 = sign(data, kp.privateKey);
    expect(Buffer.compare(sig1, sig2)).toBe(0);
  });

  it('different keys produce different signatures', () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const data = Buffer.from('same data');
    const sig1 = sign(data, kp1.privateKey);
    const sig2 = sign(data, kp2.privateKey);
    expect(Buffer.compare(sig1, sig2)).not.toBe(0);
  });
});

describe('hashData', () => {
  it('returns sha256:<64hex> format', () => {
    const result = hashData(Buffer.from('hello'));
    expect(result).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('is deterministic', () => {
    const a = hashData(Buffer.from('test'));
    const b = hashData(Buffer.from('test'));
    expect(a).toBe(b);
  });

  it('different data produces different hashes', () => {
    const a = hashData(Buffer.from('a'));
    const b = hashData(Buffer.from('b'));
    expect(a).not.toBe(b);
  });
});

describe('safeHashCompare', () => {
  it('returns true for equal buffers', () => {
    const a = Buffer.from('abcd');
    const b = Buffer.from('abcd');
    expect(safeHashCompare(a, b)).toBe(true);
  });

  it('returns false for different buffers', () => {
    const a = Buffer.from('abcd');
    const b = Buffer.from('abce');
    expect(safeHashCompare(a, b)).toBe(false);
  });

  it('returns false for different lengths', () => {
    const a = Buffer.from('abc');
    const b = Buffer.from('abcd');
    expect(safeHashCompare(a, b)).toBe(false);
  });
});

describe('parseHashString', () => {
  it('parses valid hash', () => {
    const hex = 'a'.repeat(64);
    const result = parseHashString(`sha256:${hex}`);
    expect(result.algorithm).toBe('sha256');
    expect(result.hex).toBe(hex);
  });

  it('rejects uppercase algorithm', () => {
    expect(() => parseHashString(`SHA256:${'a'.repeat(64)}`)).toThrow();
  });

  it('rejects uppercase hex', () => {
    expect(() => parseHashString(`sha256:${'A'.repeat(64)}`)).toThrow();
  });

  it('rejects wrong length', () => {
    expect(() => parseHashString(`sha256:${'a'.repeat(63)}`)).toThrow();
    expect(() => parseHashString(`sha256:${'a'.repeat(65)}`)).toThrow();
  });

  it('rejects missing prefix', () => {
    expect(() => parseHashString('a'.repeat(64))).toThrow();
  });

  it('rejects empty string', () => {
    expect(() => parseHashString('')).toThrow();
  });
});

describe('base64url', () => {
  it('round-trips', () => {
    const original = Buffer.from('hello world');
    const encoded = base64urlEncode(original);
    const decoded = base64urlDecode(encoded);
    expect(Buffer.compare(original, decoded)).toBe(0);
  });

  it('uses url-safe characters', () => {
    const data = Buffer.from([255, 254, 253, 252]);
    const encoded = base64urlEncode(data);
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
  });
});
