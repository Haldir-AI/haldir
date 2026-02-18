import type {
  Publisher,
  Skill,
  SkillVersion,
  Submission,
  Advisory,
  SearchQuery,
  SearchResult,
} from '../types.js';
import type { PatternBundle } from '@haldir/scanner';

export interface RegistryStore {
  // Publishers
  getPublisher(id: string): Promise<Publisher | null>;
  createPublisher(publisher: Publisher): Promise<void>;
  updatePublisher(id: string, updates: Partial<Publisher>): Promise<void>;
  getPublisherByApiKey(apiKeyHash: string): Promise<Publisher | null>;

  // Skills
  getSkill(name: string): Promise<Skill | null>;
  getSkillVersion(name: string, version: string): Promise<SkillVersion | null>;
  getSkillVersions(name: string): Promise<SkillVersion[]>;
  createSkill(skill: Skill): Promise<void>;
  updateSkill(name: string, updates: Partial<Skill>): Promise<void>;
  createSkillVersion(version: SkillVersion): Promise<void>;
  updateSkillVersion(name: string, version: string, updates: Partial<SkillVersion>): Promise<void>;
  searchSkills(query: SearchQuery): Promise<SearchResult>;

  // Submissions
  getSubmission(id: string): Promise<Submission | null>;
  createSubmission(submission: Submission): Promise<void>;
  updateSubmission(id: string, updates: Partial<Submission>): Promise<void>;
  listSubmissions(publisherId: string): Promise<Submission[]>;

  // Advisories
  getAdvisory(id: string): Promise<Advisory | null>;
  listAdvisories(): Promise<Advisory[]>;
  createAdvisory(advisory: Advisory): Promise<void>;

  // Pattern bundles
  addPatternBundle(bundle: PatternBundle): Promise<void>;
  getPatternBundle(version: string): Promise<PatternBundle | null>;
  getLatestPatternBundle(): Promise<PatternBundle | null>;
  listPatternVersions(): Promise<string[]>;
}
