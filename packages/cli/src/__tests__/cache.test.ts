import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, utimes } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { PatternBundle } from '@haldir/scanner';
import { setCacheDir, getCachedBundle, getStaleCachedBundle, cacheBundle, CACHE_TTL_MS } from '../cache.js';

const BUNDLE: PatternBundle = {
  version: '1.0.0',
  releasedAt: '2026-02-14T00:00:00Z',
  patternCount: 1,
  patterns: [
    { id: 'p1', category: 'exfiltration', severity: 'high', name: 'Test', description: 'D', regex: { source: 'foo', flags: '' }, fileExtensions: ['js'] },
  ],
};

describe('cache', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), 'haldir-cache-'));
    setCacheDir(tmpDir);
  });

  afterEach(async () => {
    await rm(tmpDir, { recursive: true, force: true });
  });

  it('getCachedBundle returns null when empty', async () => {
    expect(await getCachedBundle()).toBeNull();
  });

  it('getCachedBundle with version returns null when empty', async () => {
    expect(await getCachedBundle('1.0.0')).toBeNull();
  });

  it('cacheBundle + getCachedBundle round-trip (latest)', async () => {
    await cacheBundle(BUNDLE);
    const result = await getCachedBundle();
    expect(result).not.toBeNull();
    expect(result!.version).toBe('1.0.0');
    expect(result!.patterns).toHaveLength(1);
  });

  it('cacheBundle + getCachedBundle round-trip (versioned)', async () => {
    await cacheBundle(BUNDLE);
    const result = await getCachedBundle('1.0.0');
    expect(result).not.toBeNull();
    expect(result!.version).toBe('1.0.0');
  });

  it('getCachedBundle returns null when cache is stale', async () => {
    await cacheBundle(BUNDLE);
    const latestPath = join(tmpDir, 'patterns-latest.json');
    const staleTime = new Date(Date.now() - CACHE_TTL_MS - 1000);
    await utimes(latestPath, staleTime, staleTime);
    expect(await getCachedBundle()).toBeNull();
  });

  it('getStaleCachedBundle returns stale cache', async () => {
    await cacheBundle(BUNDLE);
    const latestPath = join(tmpDir, 'patterns-latest.json');
    const staleTime = new Date(Date.now() - CACHE_TTL_MS - 1000);
    await utimes(latestPath, staleTime, staleTime);
    const result = await getStaleCachedBundle();
    expect(result).not.toBeNull();
    expect(result!.version).toBe('1.0.0');
  });

  it('getStaleCachedBundle returns null when no cache exists', async () => {
    expect(await getStaleCachedBundle()).toBeNull();
  });

  it('cacheBundle writes both version and latest files', async () => {
    const v2: PatternBundle = { ...BUNDLE, version: '2.0.0' };
    await cacheBundle(BUNDLE);
    await cacheBundle(v2);
    const v1 = await getCachedBundle('1.0.0');
    const latest = await getCachedBundle();
    expect(v1!.version).toBe('1.0.0');
    expect(latest!.version).toBe('2.0.0');
  });
});
