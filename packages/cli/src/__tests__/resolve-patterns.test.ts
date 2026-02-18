import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, utimes } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { PATTERN_DB } from '@haldir/scanner';
import type { PatternBundle } from '@haldir/scanner';
import { setCacheDir, cacheBundle, CACHE_TTL_MS } from '../cache.js';
import { resolvePatterns } from '../commands/scan.js';

const BUNDLE: PatternBundle = {
  version: '1.0.0',
  releasedAt: '2026-02-14T00:00:00Z',
  patternCount: 2,
  patterns: [
    { id: 'p1', category: 'exfiltration', severity: 'high', name: 'P1', description: 'D1', regex: { source: 'test_pattern_1', flags: '' }, fileExtensions: ['js'] },
    { id: 'p2', category: 'obfuscation', severity: 'medium', name: 'P2', description: 'D2', regex: { source: 'test_pattern_2', flags: 'i' }, fileExtensions: ['ts'] },
  ],
};

vi.mock('../registry-client.js', () => ({
  fetchPatternBundle: vi.fn(),
}));

import { fetchPatternBundle } from '../registry-client.js';
const mockFetch = fetchPatternBundle as ReturnType<typeof vi.fn>;

describe('resolvePatterns', () => {
  let tmpDir: string;
  const originalError = console.error;

  beforeEach(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), 'haldir-resolve-'));
    setCacheDir(tmpDir);
    mockFetch.mockReset();
    console.error = vi.fn();
  });

  afterEach(async () => {
    await rm(tmpDir, { recursive: true, force: true });
    console.error = originalError;
  });

  it('no registry → built-in patterns', async () => {
    const result = await resolvePatterns({});
    expect(result.source).toBe('built-in');
    expect(result.version).toBe('built-in');
    expect(result.patterns).toHaveLength(PATTERN_DB.length);
  });

  it('offline + no cache → built-in', async () => {
    const result = await resolvePatterns({ offline: true });
    expect(result.source).toBe('built-in');
  });

  it('offline + fresh cache (no registry) → cache', async () => {
    await cacheBundle(BUNDLE);
    const result = await resolvePatterns({ offline: true });
    expect(result.source).toBe('cache (offline)');
    expect(result.version).toBe('1.0.0');
    expect(result.patterns).toHaveLength(2);
  });

  it('offline + fresh cache (with registry) → cache', async () => {
    await cacheBundle(BUNDLE);
    const result = await resolvePatterns({ registry: 'http://r', offline: true });
    expect(result.source).toBe('cache (offline)');
    expect(result.version).toBe('1.0.0');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('offline + stale cache → stale cache', async () => {
    await cacheBundle(BUNDLE);
    const latestPath = join(tmpDir, 'patterns-latest.json');
    const staleTime = new Date(Date.now() - CACHE_TTL_MS - 1000);
    await utimes(latestPath, staleTime, staleTime);

    const result = await resolvePatterns({ offline: true });
    expect(result.source).toBe('cache (offline, stale)');
    expect(result.version).toBe('1.0.0');
  });

  it('registry + fresh cache → uses cache (no fetch)', async () => {
    await cacheBundle(BUNDLE);
    const result = await resolvePatterns({ registry: 'http://r' });
    expect(result.source).toBe('cache');
    expect(result.version).toBe('1.0.0');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('registry + no cache → fetches from registry', async () => {
    mockFetch.mockResolvedValue(BUNDLE);
    const result = await resolvePatterns({ registry: 'http://r' });
    expect(result.source).toBe('registry');
    expect(result.version).toBe('1.0.0');
    expect(result.patterns).toHaveLength(2);
    expect(mockFetch).toHaveBeenCalledWith('http://r', undefined);
  });

  it('registry + fetch fail + stale cache → stale cache + warning', async () => {
    await cacheBundle(BUNDLE);
    const latestPath = join(tmpDir, 'patterns-latest.json');
    const staleTime = new Date(Date.now() - CACHE_TTL_MS - 1000);
    await utimes(latestPath, staleTime, staleTime);

    mockFetch.mockRejectedValue(new Error('network'));
    const result = await resolvePatterns({ registry: 'http://r' });
    expect(result.source).toBe('cache (stale)');
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining('stale cache'));
  });

  it('registry + fetch fail + no cache → built-in + warning', async () => {
    mockFetch.mockRejectedValue(new Error('network'));
    const result = await resolvePatterns({ registry: 'http://r' });
    expect(result.source).toBe('built-in');
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining('built-in'));
  });

  it('passes patternVersion to fetch', async () => {
    mockFetch.mockResolvedValue(BUNDLE);
    await resolvePatterns({ registry: 'http://r', patternVersion: '1.0.0' });
    expect(mockFetch).toHaveBeenCalledWith('http://r', '1.0.0');
  });

  it('registry fetch caches the bundle', async () => {
    mockFetch.mockResolvedValue(BUNDLE);
    await resolvePatterns({ registry: 'http://r' });

    mockFetch.mockReset();
    const result = await resolvePatterns({ registry: 'http://r' });
    expect(result.source).toBe('cache');
    expect(mockFetch).not.toHaveBeenCalled();
  });
});
