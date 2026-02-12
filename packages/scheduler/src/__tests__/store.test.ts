import { describe, it, expect, beforeEach } from 'vitest';
import { MemoryRescanStore } from '../store.js';
import type { RescanJob, SkillRecord } from '../types.js';

describe('MemoryRescanStore', () => {
  let store: MemoryRescanStore;

  beforeEach(() => {
    store = new MemoryRescanStore();
  });

  describe('jobs', () => {
    const job: RescanJob = {
      id: 'rescan-1',
      skillName: 'test-skill',
      version: '1.0.0',
      publisherId: 'pub-1',
      publisherTier: 'unverified',
      trigger: 'scheduled',
      status: 'pending',
      createdAt: '2025-01-01T00:00:00Z',
    };

    it('creates and retrieves by status', async () => {
      await store.createJob(job);
      const pending = await store.getJobsByStatus('pending');
      expect(pending).toHaveLength(1);
      expect(pending[0].id).toBe('rescan-1');
    });

    it('updates job', async () => {
      await store.createJob(job);
      await store.updateJob('rescan-1', { status: 'running', startedAt: '2025-01-01T01:00:00Z' });
      const running = await store.getJobsByStatus('running');
      expect(running).toHaveLength(1);
    });

    it('lists recent jobs', async () => {
      await store.createJob(job);
      await store.createJob({ ...job, id: 'rescan-2', createdAt: '2025-01-02T00:00:00Z' });
      const recent = await store.listRecentJobs(1);
      expect(recent).toHaveLength(1);
      expect(recent[0].id).toBe('rescan-2');
    });
  });

  describe('skills due for rescan', () => {
    beforeEach(() => {
      store.addSkill({
        name: 'old-skill', version: '1.0.0', publisherId: 'pub-1',
        publisherTier: 'unverified', lastScannedAt: '2025-01-01T00:00:00Z',
      });
      store.addSkill({
        name: 'new-skill', version: '1.0.0', publisherId: 'pub-1',
        publisherTier: 'unverified', lastScannedAt: '2025-06-01T00:00:00Z',
      });
      store.addSkill({
        name: 'never-scanned', version: '1.0.0', publisherId: 'pub-1',
        publisherTier: 'unverified',
      });
    });

    it('returns skills scanned before cutoff', async () => {
      const due = await store.getSkillsDueForRescan('unverified', '2025-03-01T00:00:00Z');
      expect(due).toHaveLength(2);
    });

    it('filters by tier', async () => {
      store.addSkill({
        name: 'verified-skill', version: '1.0.0', publisherId: 'pub-2',
        publisherTier: 'verified', lastScannedAt: '2025-01-01T00:00:00Z',
      });
      const due = await store.getSkillsDueForRescan('verified', '2025-03-01T00:00:00Z');
      expect(due).toHaveLength(1);
      expect(due[0].name).toBe('verified-skill');
    });

    it('updates scan date', async () => {
      await store.updateSkillScanDate('old-skill', '1.0.0', '2025-07-01T00:00:00Z');
      const due = await store.getSkillsDueForRescan('unverified', '2025-03-01T00:00:00Z');
      const names = due.map(s => s.name);
      expect(names).not.toContain('old-skill');
    });
  });
});
