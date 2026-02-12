import { randomBytes } from 'node:crypto';
import type {
  SchedulerConfig,
  RescanJob,
  RescanResult,
  SkillRecord,
  PublisherTier,
} from './types.js';
import { getRescanInterval } from './policy.js';

const TIERS: PublisherTier[] = ['unverified', 'verified', 'trusted', 'hydracore'];

export class RescanScheduler {
  private config: SchedulerConfig;
  private timer: ReturnType<typeof setInterval> | null = null;
  private running = false;

  constructor(config: SchedulerConfig) {
    this.config = config;
  }

  async tick(): Promise<RescanJob[]> {
    const jobs: RescanJob[] = [];
    const now = new Date();
    const batchSize = this.config.batchSize ?? 50;

    for (const tier of TIERS) {
      const interval = getRescanInterval(tier, this.config.policy);
      if (interval === 0) continue;

      const cutoff = new Date(now.getTime() - interval).toISOString();
      const dueSkills = await this.config.store.getSkillsDueForRescan(tier, cutoff);

      for (const skill of dueSkills.slice(0, batchSize)) {
        const job = await this.processSkill(skill);
        jobs.push(job);
      }
    }

    return jobs;
  }

  private async processSkill(skill: SkillRecord): Promise<RescanJob> {
    const jobId = `rescan-${Date.now()}-${randomBytes(4).toString('hex')}`;
    const now = new Date().toISOString();

    const job: RescanJob = {
      id: jobId,
      skillName: skill.name,
      version: skill.version,
      publisherId: skill.publisherId,
      publisherTier: skill.publisherTier,
      trigger: 'scheduled',
      status: 'running',
      createdAt: now,
      startedAt: now,
    };

    await this.config.store.createJob(job);

    if (this.config.dryRun) {
      await this.config.store.updateJob(jobId, {
        status: 'passed',
        completedAt: now,
        result: { passed: true, action: 'none', details: 'dry run' },
      });
      return { ...job, status: 'passed', completedAt: now };
    }

    try {
      const result = await this.config.onRescan(skill);
      const completedAt = new Date().toISOString();

      await this.config.store.updateJob(jobId, {
        status: result.passed ? 'passed' : 'failed',
        completedAt,
        result,
      });

      await this.config.store.updateSkillScanDate(skill.name, skill.version, completedAt);

      if (!result.passed) {
        await this.handleFailure(skill, result);
      }

      return { ...job, status: result.passed ? 'passed' : 'failed', completedAt, result };
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      await this.config.store.updateJob(jobId, {
        status: 'error',
        completedAt: new Date().toISOString(),
        error: errorMsg,
      });
      return { ...job, status: 'error', error: errorMsg };
    }
  }

  private async handleFailure(skill: SkillRecord, result: RescanResult): Promise<void> {
    if (result.action === 'revoke' && this.config.onRevoke) {
      await this.config.onRevoke(skill, result);
    }
    if (result.action === 'advisory' && this.config.onAdvisory) {
      await this.config.onAdvisory(skill, result);
    }
  }

  async triggerManual(skill: SkillRecord, trigger: 'cve_update' | 'pattern_update' | 'community_report' | 'manual' = 'manual'): Promise<RescanJob> {
    const jobId = `rescan-${Date.now()}-${randomBytes(4).toString('hex')}`;
    const now = new Date().toISOString();

    const job: RescanJob = {
      id: jobId,
      skillName: skill.name,
      version: skill.version,
      publisherId: skill.publisherId,
      publisherTier: skill.publisherTier,
      trigger,
      status: 'running',
      createdAt: now,
      startedAt: now,
    };

    await this.config.store.createJob(job);

    try {
      const result = await this.config.onRescan(skill);
      const completedAt = new Date().toISOString();

      await this.config.store.updateJob(jobId, {
        status: result.passed ? 'passed' : 'failed',
        completedAt,
        result,
      });

      await this.config.store.updateSkillScanDate(skill.name, skill.version, completedAt);

      if (!result.passed) {
        await this.handleFailure(skill, result);
      }

      return { ...job, status: result.passed ? 'passed' : 'failed', completedAt, result };
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      await this.config.store.updateJob(jobId, {
        status: 'error',
        completedAt: new Date().toISOString(),
        error: errorMsg,
      });
      return { ...job, status: 'error', error: errorMsg };
    }
  }

  start(intervalMs: number = 60_000): void {
    if (this.running) return;
    this.running = true;
    this.timer = setInterval(() => void this.tick(), intervalMs);
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.running = false;
  }

  isRunning(): boolean {
    return this.running;
  }
}
