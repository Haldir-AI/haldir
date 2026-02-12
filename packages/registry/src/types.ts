export type PublisherTier = 'unverified' | 'verified' | 'trusted' | 'hydracore';
export type SkillType = 'skill.md' | 'mcp';
export type SubmissionStatus = 'queued' | 'vetting' | 'approved' | 'rejected' | 'amber';

export interface Publisher {
  id: string;
  displayName: string;
  tier: PublisherTier;
  createdAt: string;
  verifiedAt?: string;
  totalApproved: number;
  totalRejected: number;
  totalRevoked: number;
  apiKeyHash?: string;
}

export interface Skill {
  id: string;
  name: string;
  type: SkillType;
  description?: string;
  author: string;
  latestVersion: string;
  createdAt: string;
  updatedAt: string;
  publisherId: string;
  downloads: number;
  trustScore?: number;
}

export interface SkillVersion {
  skillId: string;
  version: string;
  publishedAt: string;
  status: SubmissionStatus;
  trustScore?: number;
  vettingResults?: VettingResults;
  tarballPath?: string;
}

export interface VettingResults {
  pipelineVersion: string;
  completedAt: string;
  layers: Record<string, LayerResult>;
  overallTrust: number;
  verdict: 'approved' | 'rejected' | 'amber';
}

export interface LayerResult {
  status: string;
  duration_ms: number;
  details?: Record<string, unknown>;
}

export interface Submission {
  id: string;
  skillName: string;
  version: string;
  type: SkillType;
  publisherId: string;
  status: SubmissionStatus;
  createdAt: string;
  completedAt?: string;
  vettingPath: 'full' | 'expedited';
  vettingResults?: VettingResults;
  error?: string;
}

export interface Advisory {
  id: string;
  skillName: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  publishedAt: string;
  affectedVersions: string[];
}

export interface SearchQuery {
  q?: string;
  type?: SkillType;
  tier?: PublisherTier;
  sort?: 'downloads' | 'trust_score' | 'recently_updated';
  limit?: number;
  offset?: number;
}

export interface SearchResult {
  skills: Skill[];
  total: number;
  limit: number;
  offset: number;
}
