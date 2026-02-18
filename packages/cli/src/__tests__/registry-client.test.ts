import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { fetchPatternBundle } from '../registry-client.js';

const mockBundle = {
  version: '1.0.0',
  releasedAt: '2026-02-14T00:00:00Z',
  patternCount: 1,
  patterns: [],
};

describe('fetchPatternBundle', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    globalThis.fetch = vi.fn();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('fetches latest patterns', async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockBundle),
    });

    const result = await fetchPatternBundle('http://localhost:3000');
    expect(result.version).toBe('1.0.0');
    expect(globalThis.fetch).toHaveBeenCalledWith(
      'http://localhost:3000/v1/scanner/patterns',
      expect.objectContaining({ headers: { Accept: 'application/json' } }),
    );
  });

  it('fetches specific version', async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockBundle),
    });

    await fetchPatternBundle('http://localhost:3000', '1.0.0');
    expect(globalThis.fetch).toHaveBeenCalledWith(
      'http://localhost:3000/v1/scanner/patterns/1.0.0',
      expect.any(Object),
    );
  });

  it('strips trailing slashes from URL', async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockBundle),
    });

    await fetchPatternBundle('http://localhost:3000///');
    expect(globalThis.fetch).toHaveBeenCalledWith(
      'http://localhost:3000/v1/scanner/patterns',
      expect.any(Object),
    );
  });

  it('throws on invalid semver version', async () => {
    await expect(fetchPatternBundle('http://localhost:3000', 'not-semver'))
      .rejects.toThrow('Invalid pattern version');
  });

  it('throws on non-ok response', async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: false,
      status: 404,
      statusText: 'Not Found',
    });

    await expect(fetchPatternBundle('http://localhost:3000'))
      .rejects.toThrow('Registry returned 404');
  });
});
