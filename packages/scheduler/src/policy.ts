import type { PublisherTier, RescanPolicy } from './types.js';

const DAY_MS = 24 * 60 * 60 * 1000;

export const DEFAULT_POLICY: RescanPolicy = {
  unverified: 7 * DAY_MS,
  verified: 14 * DAY_MS,
  trusted: 30 * DAY_MS,
  hydracore: 0,
};

export function getRescanInterval(tier: PublisherTier, policy: RescanPolicy): number {
  return policy[tier];
}

export function isDueForRescan(
  tier: PublisherTier,
  lastScannedAt: string | undefined,
  policy: RescanPolicy,
  now: number = Date.now(),
): boolean {
  const interval = getRescanInterval(tier, policy);
  if (interval === 0) return false;
  if (!lastScannedAt) return true;
  return now - new Date(lastScannedAt).getTime() >= interval;
}

export function nextRescanDate(
  tier: PublisherTier,
  lastScannedAt: string,
  policy: RescanPolicy,
): string | null {
  const interval = getRescanInterval(tier, policy);
  if (interval === 0) return null;
  const next = new Date(lastScannedAt).getTime() + interval;
  return new Date(next).toISOString();
}
