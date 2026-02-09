import { describe, it, expect } from 'vitest';
import { canonicalize, canonicalizeToBuffer } from '../canonical.js';

describe('canonical', () => {
  it('sorts object keys', () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it('removes whitespace', () => {
    expect(canonicalize({ a: 1 })).toBe('{"a":1}');
  });

  it('handles nested objects', () => {
    expect(canonicalize({ z: { b: 1, a: 2 }, a: 3 })).toBe('{"a":3,"z":{"a":2,"b":1}}');
  });

  it('preserves array order', () => {
    expect(canonicalize([3, 1, 2])).toBe('[3,1,2]');
  });

  it('handles null', () => {
    expect(canonicalize({ a: null })).toBe('{"a":null}');
  });

  it('handles boolean', () => {
    expect(canonicalize({ t: true, f: false })).toBe('{"f":false,"t":true}');
  });

  it('handles empty object', () => {
    expect(canonicalize({})).toBe('{}');
  });

  it('handles empty array', () => {
    expect(canonicalize([])).toBe('[]');
  });

  it('handles empty string', () => {
    expect(canonicalize({ a: '' })).toBe('{"a":""}');
  });

  // RFC 8785 number edge cases
  it('represents integers without decimal', () => {
    expect(canonicalize({ n: 1 })).toBe('{"n":1}');
  });

  it('handles negative zero as 0', () => {
    expect(canonicalize({ n: -0 })).toBe('{"n":0}');
  });

  it('handles large exponent numbers', () => {
    const result = canonicalize({ n: 1e20 });
    expect(result).toBe('{"n":100000000000000000000}');
  });

  it('handles small decimals', () => {
    const result = canonicalize({ n: 0.1 });
    expect(result).toContain('0.1');
  });

  // Unicode
  it('handles unicode strings', () => {
    const result = canonicalize({ key: '\u00e9' }); // é
    expect(result).toBe('{"key":"é"}');
  });

  it('escapes control characters', () => {
    const result = canonicalize({ a: '\n' });
    expect(result).toBe('{"a":"\\n"}');
  });

  // canonicalizeToBuffer
  it('returns Buffer from canonicalizeToBuffer', () => {
    const buf = canonicalizeToBuffer({ a: 1 });
    expect(Buffer.isBuffer(buf)).toBe(true);
    expect(buf.toString('utf-8')).toBe('{"a":1}');
  });

  // Pinned library compatibility tests
  it('produces deterministic output for complex nested structure', () => {
    const input = {
      z: [1, { c: 3, a: 1, b: 2 }],
      a: 'hello',
      m: { x: null, w: true, v: false },
    };
    const expected = '{"a":"hello","m":{"v":false,"w":true,"x":null},"z":[1,{"a":1,"b":2,"c":3}]}';
    expect(canonicalize(input)).toBe(expected);
  });

  it('handles deeply nested structure deterministically', () => {
    const input = { d: { c: { b: { a: 1 } } } };
    expect(canonicalize(input)).toBe('{"d":{"c":{"b":{"a":1}}}}');
  });
});
