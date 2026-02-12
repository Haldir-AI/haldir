import { describe, it, expect, beforeEach, vi } from 'vitest';
import { RescanScheduler } from '../scheduler.js';
import { MemoryRescanStore } from '../store.js';
import { DEFAULT_POLICY } from '../policy.js';
import type { SkillRecord, RescanResult, SchedulerConfig } from '../types.js';

describe('RescanScheduler', () => {
  let store: MemoryRescanStore;
  let onRescan: ReturnType<typeof vi.fn>;
  let onRevoke: ReturnType<typeof vi.fn>;
  let onAdvisory: ReturnType<typeof vi.fn>;
  let scheduler: RescanScheduler;

  beforeEach(() => {
    store = new MemoryRescanStore();
    onRescan = vi.fn<(skill: SkillRecord) => Promise<RescanResult>>().mockResolvedValue({
      passed: true,
      trustScore: 95,
      action: 'none',
    });
    onRevoke = vi.fn().mockResolvedValue(undefined);
    onAdvisory = vi.fn().mockResolvedValue(undefined);
    scheduler = new RescanScheduler({
      store,
      policy: DEFAULT_POLICY,
      onRescan,
      onRevoke,
      onAdvisory,
    });
  });

  it('processes due skills on tick', async () => {
    store.addSkill({
      name: 'stale-skill', version: '1.0.0', publisherId: 'pub-1',
      publisherTier: 'unverified',
      lastScannedAt: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString(),
    });

    const jobs = await scheduler.tick();
    expect(jobs).toHaveLength(1);
    expect(jobs[0].status).toBe('passed');
    expect(onRescan).toHaveBeenCalledOnce();
  });

  it('skips hydracore skills', async () => {
    store.addSkill({
      name: 'internal', version: '1.0.0', publisherId: 'pub-1',
      publisherTier: 'hydracore',
      lastScannedAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString(),
    });

    const jobs = await scheduler.tick();
    expect(jobs).toHaveLength(0);
  });

  it('skips recently scanned skills', async () => {
    store.addSkill({
      name: 'fresh', version: '1.0.0', publisherId: 'pub-1',
      publisherTier: 'unverified',
      lastScannedAt: new Date().toISOString(),
    });

    const jobs = await scheduler.tick();
    expect(jobs).toHaveLength(0);
  });

  it('calls onRevoke when result action is revoke', async () => {
    store.addSkill({
      name: 'bad-skill', version: '1.0.0', publisherId: 'pub-1',
      publisherTier: 'unverified',
    });

    onRescan.mockResolvedValueOnce({
      passed: false,
      action: 'revoke',
      details: 'New vulnerability detected',
    });

    const jobs = await scheduler.tick();
    expect(jobs[0].status).toBe('failed');
    expect(onRevoke).toHaveBeenCalledOnce();
  });

  it('calls onAdvisory when result action is advisory', async () => {
    store.addSkill({
      name: 'risky-skill', version: '1.0.0', publisherId: 'pub-1',
      publisherTier: 'unverified',
    });

    onRescan.mockResolvedValueOnce({
      passed: false,
      action: 'advisory',
      details: 'Dependency CVE found',
    });

    const jobs = await scheduler.tick();
    expect(jobs[0].status).toBe('failed');
    expect(onAdvisory).toHaveBeenCalledOnce();
  });

  it('handles rescan errors gracefully', async () => {
    store.addSkill({
      name: 'error-skill', version: '1.0.0', publisherId: 'pub-1',
      publisherTier: 'unverified',
    });

    onRescan.mockRejectedValueOnce(new Error('pipeline crash'));

    const jobs = await scheduler.tick();
    expect(jobs[0].status).toBe('error');
    expect(jobs[0].error).toBe('pipeline crash');
  });

  it('dry run creates jobs without calling onRescan', async () => {
    const dryScheduler = new RescanScheduler({
      store,
      policy: DEFAULT_POLICY,
      onRescan,
      dryRun: true,
    });

    store.addSkill({
      name: 'dry-skill', version: '1.0.0', publisherId: 'pub-1',
      publisherTier: 'unverified',
    });

    const jobs = await dryScheduler.tick();
    expect(jobs).toHaveLength(1);
    expect(jobs[0].status).toBe('passed');
    expect(onRescan).not.toHaveBeenCalled();
  });

  it('triggerManual rescans a specific skill', async () => {
    const skill: SkillRecord = {
      name: 'manual-scan', version: '2.0.0', publisherId: 'pub-1',
      publisherTier: 'verified',
    };
    store.addSkill(skill);

    const job = await scheduler.triggerManual(skill, 'cve_update');
    expect(job.trigger).toBe('cve_update');
    expect(job.status).toBe('passed');
    expect(onRescan).toHaveBeenCalledWith(skill);
  });

  it('start and stop lifecycle', () => {
    expect(scheduler.isRunning()).toBe(false);
    scheduler.start(60000);
    expect(scheduler.isRunning()).toBe(true);
    scheduler.stop();
    expect(scheduler.isRunning()).toBe(false);
  });

  it('multiple tiers processed in single tick', async () => {
    store.addSkill({
      name: 'unv-skill', version: '1.0.0', publisherId: 'pub-1',
      publisherTier: 'unverified',
      lastScannedAt: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString(),
    });
    store.addSkill({
      name: 'ver-skill', version: '1.0.0', publisherId: 'pub-2',
      publisherTier: 'verified',
      lastScannedAt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString(),
    });

    const jobs = await scheduler.tick();
    expect(jobs).toHaveLength(2);
  });
});
