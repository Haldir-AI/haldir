export type PublisherTier = 'unverified' | 'verified' | 'trusted' | 'hydracore';

export type RescanTrigger =
  | 'scheduled'
  | 'cve_update'
  | 'pattern_update'
  | 'publisher_downgrade'
  | 'community_report'
  | 'manual';

export type RescanStatus = 'pending' | 'running' | 'passed' | 'failed' | 'error';

export interface RescanPolicy {
  unverified: number;
  verified: number;
  trusted: number;
  hydracore: number;
}

export interface RescanJob {
  id: string;
  skillName: string;
  version: string;
  publisherId: string;
  publisherTier: PublisherTier;
  trigger: RescanTrigger;
  status: RescanStatus;
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
  result?: RescanResult;
  error?: string;
}

export interface RescanResult {
  passed: boolean;
  trustScore?: number;
  findings?: number;
  action: 'none' | 'downgrade_trust' | 'revoke' | 'advisory';
  details?: string;
}

export interface SkillRecord {
  name: string;
  version: string;
  publisherId: string;
  publisherTier: PublisherTier;
  lastScannedAt?: string;
  trustScore?: number;
}

export interface RescanStore {
  getJobsByStatus(status: RescanStatus): Promise<RescanJob[]>;
  createJob(job: RescanJob): Promise<void>;
  updateJob(id: string, updates: Partial<RescanJob>): Promise<void>;
  getSkillsDueForRescan(tier: PublisherTier, beforeDate: string): Promise<SkillRecord[]>;
  updateSkillScanDate(name: string, version: string, date: string): Promise<void>;
  listRecentJobs(limit: number): Promise<RescanJob[]>;
}

export interface SchedulerConfig {
  store: RescanStore;
  policy: RescanPolicy;
  onRescan: (skill: SkillRecord) => Promise<RescanResult>;
  onRevoke?: (skill: SkillRecord, result: RescanResult) => Promise<void>;
  onAdvisory?: (skill: SkillRecord, result: RescanResult) => Promise<void>;
  batchSize?: number;
  dryRun?: boolean;
}
