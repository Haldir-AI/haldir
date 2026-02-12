import type {
  RescanStore,
  RescanJob,
  RescanStatus,
  SkillRecord,
  PublisherTier,
} from './types.js';

export class MemoryRescanStore implements RescanStore {
  private jobs = new Map<string, RescanJob>();
  private skills = new Map<string, SkillRecord>();

  addSkill(skill: SkillRecord): void {
    this.skills.set(`${skill.name}@${skill.version}`, skill);
  }

  async getJobsByStatus(status: RescanStatus): Promise<RescanJob[]> {
    return [...this.jobs.values()].filter(j => j.status === status);
  }

  async createJob(job: RescanJob): Promise<void> {
    this.jobs.set(job.id, job);
  }

  async updateJob(id: string, updates: Partial<RescanJob>): Promise<void> {
    const existing = this.jobs.get(id);
    if (existing) this.jobs.set(id, { ...existing, ...updates });
  }

  async getSkillsDueForRescan(tier: PublisherTier, beforeDate: string): Promise<SkillRecord[]> {
    const cutoff = new Date(beforeDate).getTime();
    return [...this.skills.values()].filter(s => {
      if (s.publisherTier !== tier) return false;
      if (!s.lastScannedAt) return true;
      return new Date(s.lastScannedAt).getTime() < cutoff;
    });
  }

  async updateSkillScanDate(name: string, version: string, date: string): Promise<void> {
    const key = `${name}@${version}`;
    const existing = this.skills.get(key);
    if (existing) this.skills.set(key, { ...existing, lastScannedAt: date });
  }

  async listRecentJobs(limit: number): Promise<RescanJob[]> {
    return [...this.jobs.values()]
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .slice(0, limit);
  }
}
