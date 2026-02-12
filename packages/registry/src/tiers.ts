import type { Publisher, PublisherTier } from './types.js';

const VERIFIED_MIN_APPROVED = 5;
const VERIFIED_MAX_REJECTED = 0;
const VERIFIED_MIN_AGE_MS = 90 * 24 * 60 * 60 * 1000;

export function computeTier(publisher: Publisher): PublisherTier {
  if (publisher.tier === 'hydracore' || publisher.tier === 'trusted') {
    return publisher.tier;
  }

  if (publisher.totalRevoked > 0) return 'unverified';

  if (
    publisher.totalApproved >= VERIFIED_MIN_APPROVED &&
    publisher.totalRejected <= VERIFIED_MAX_REJECTED &&
    publisher.createdAt &&
    Date.now() - new Date(publisher.createdAt).getTime() >= VERIFIED_MIN_AGE_MS
  ) {
    return 'verified';
  }

  return 'unverified';
}

export function getVettingPath(tier: PublisherTier, isUpdate: boolean): 'full' | 'expedited' {
  if (!isUpdate) return 'full';
  if (tier === 'hydracore') return 'expedited';
  if (tier === 'trusted') return 'expedited';
  if (tier === 'verified') return 'expedited';
  return 'full';
}

export function getSkipLayers(tier: PublisherTier, isUpdate: boolean): number[] {
  if (!isUpdate) return [];
  if (tier === 'hydracore') return [1, 2, 3, 4];
  if (tier === 'trusted') return [3, 4];
  if (tier === 'verified') return [3];
  return [];
}

export function shouldDemote(publisher: Publisher): boolean {
  return publisher.totalRevoked > 0 && publisher.tier !== 'unverified';
}
