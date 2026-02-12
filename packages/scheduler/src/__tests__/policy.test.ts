import { describe, it, expect } from 'vitest';
import { DEFAULT_POLICY, getRescanInterval, isDueForRescan, nextRescanDate } from '../policy.js';

const DAY_MS = 24 * 60 * 60 * 1000;

describe('getRescanInterval', () => {
  it('returns 7 days for unverified', () => {
    expect(getRescanInterval('unverified', DEFAULT_POLICY)).toBe(7 * DAY_MS);
  });

  it('returns 14 days for verified', () => {
    expect(getRescanInterval('verified', DEFAULT_POLICY)).toBe(14 * DAY_MS);
  });

  it('returns 30 days for trusted', () => {
    expect(getRescanInterval('trusted', DEFAULT_POLICY)).toBe(30 * DAY_MS);
  });

  it('returns 0 for hydracore (on-update only)', () => {
    expect(getRescanInterval('hydracore', DEFAULT_POLICY)).toBe(0);
  });
});

describe('isDueForRescan', () => {
  it('returns true when never scanned', () => {
    expect(isDueForRescan('unverified', undefined, DEFAULT_POLICY)).toBe(true);
  });

  it('returns false for hydracore (interval=0)', () => {
    expect(isDueForRescan('hydracore', undefined, DEFAULT_POLICY)).toBe(false);
  });

  it('returns true when past interval', () => {
    const eightDaysAgo = new Date(Date.now() - 8 * DAY_MS).toISOString();
    expect(isDueForRescan('unverified', eightDaysAgo, DEFAULT_POLICY)).toBe(true);
  });

  it('returns false when within interval', () => {
    const twoDaysAgo = new Date(Date.now() - 2 * DAY_MS).toISOString();
    expect(isDueForRescan('unverified', twoDaysAgo, DEFAULT_POLICY)).toBe(false);
  });

  it('respects custom now parameter', () => {
    const scanned = '2025-01-01T00:00:00Z';
    const now = new Date('2025-01-10T00:00:00Z').getTime();
    expect(isDueForRescan('unverified', scanned, DEFAULT_POLICY, now)).toBe(true);
  });
});

describe('nextRescanDate', () => {
  it('returns null for hydracore', () => {
    expect(nextRescanDate('hydracore', '2025-01-01T00:00:00Z', DEFAULT_POLICY)).toBeNull();
  });

  it('returns date 7 days after last scan for unverified', () => {
    const result = nextRescanDate('unverified', '2025-01-01T00:00:00Z', DEFAULT_POLICY);
    expect(result).toBe(new Date('2025-01-08T00:00:00Z').toISOString());
  });

  it('returns date 14 days after last scan for verified', () => {
    const result = nextRescanDate('verified', '2025-01-01T00:00:00Z', DEFAULT_POLICY);
    expect(result).toBe(new Date('2025-01-15T00:00:00Z').toISOString());
  });
});
