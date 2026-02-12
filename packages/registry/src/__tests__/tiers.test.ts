import { describe, it, expect } from 'vitest';
import { computeTier, getVettingPath, getSkipLayers, shouldDemote } from '../tiers.js';
import type { Publisher } from '../types.js';

function makePublisher(overrides: Partial<Publisher> = {}): Publisher {
  return {
    id: 'pub-1',
    displayName: 'Test',
    tier: 'unverified',
    createdAt: new Date(Date.now() - 100 * 24 * 60 * 60 * 1000).toISOString(),
    totalApproved: 0,
    totalRejected: 0,
    totalRevoked: 0,
    ...overrides,
  };
}

describe('computeTier', () => {
  it('keeps hydracore tier', () => {
    expect(computeTier(makePublisher({ tier: 'hydracore' }))).toBe('hydracore');
  });

  it('keeps trusted tier', () => {
    expect(computeTier(makePublisher({ tier: 'trusted' }))).toBe('trusted');
  });

  it('demotes to unverified on revocation', () => {
    expect(computeTier(makePublisher({ tier: 'verified', totalRevoked: 1 }))).toBe('unverified');
  });

  it('promotes to verified with 5+ approved, 0 rejected, 90+ days', () => {
    expect(computeTier(makePublisher({ totalApproved: 5, totalRejected: 0 }))).toBe('verified');
  });

  it('stays unverified with < 5 approved', () => {
    expect(computeTier(makePublisher({ totalApproved: 4 }))).toBe('unverified');
  });

  it('stays unverified with rejections', () => {
    expect(computeTier(makePublisher({ totalApproved: 10, totalRejected: 1 }))).toBe('unverified');
  });

  it('stays unverified if account too young', () => {
    const recent = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();
    expect(computeTier(makePublisher({ totalApproved: 10, createdAt: recent }))).toBe('unverified');
  });
});

describe('getVettingPath', () => {
  it('returns full for new submissions', () => {
    expect(getVettingPath('unverified', false)).toBe('full');
    expect(getVettingPath('trusted', false)).toBe('full');
  });

  it('returns expedited for verified+ updates', () => {
    expect(getVettingPath('verified', true)).toBe('expedited');
    expect(getVettingPath('trusted', true)).toBe('expedited');
    expect(getVettingPath('hydracore', true)).toBe('expedited');
  });

  it('returns full for unverified updates', () => {
    expect(getVettingPath('unverified', true)).toBe('full');
  });
});

describe('getSkipLayers', () => {
  it('returns empty for new submissions', () => {
    expect(getSkipLayers('hydracore', false)).toEqual([]);
  });

  it('hydracore updates skip all layers', () => {
    expect(getSkipLayers('hydracore', true)).toEqual([1, 2, 3, 4]);
  });

  it('trusted updates skip layers 3+4', () => {
    expect(getSkipLayers('trusted', true)).toEqual([3, 4]);
  });

  it('verified updates skip layer 3', () => {
    expect(getSkipLayers('verified', true)).toEqual([3]);
  });

  it('unverified updates skip nothing', () => {
    expect(getSkipLayers('unverified', true)).toEqual([]);
  });
});

describe('shouldDemote', () => {
  it('returns true when revoked and not unverified', () => {
    expect(shouldDemote(makePublisher({ tier: 'verified', totalRevoked: 1 }))).toBe(true);
  });

  it('returns false when already unverified', () => {
    expect(shouldDemote(makePublisher({ tier: 'unverified', totalRevoked: 1 }))).toBe(false);
  });

  it('returns false when no revocations', () => {
    expect(shouldDemote(makePublisher({ tier: 'verified', totalRevoked: 0 }))).toBe(false);
  });
});
