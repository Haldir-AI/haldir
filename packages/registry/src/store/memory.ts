import { timingSafeEqual } from 'node:crypto';
import type { RegistryStore } from './types.js';
import type {
  Publisher,
  Skill,
  SkillVersion,
  Submission,
  Advisory,
  SearchQuery,
  SearchResult,
} from '../types.js';

export class MemoryStore implements RegistryStore {
  private publishers = new Map<string, Publisher>();
  private skills = new Map<string, Skill>();
  private versions = new Map<string, SkillVersion>();
  private submissions = new Map<string, Submission>();
  private advisories = new Map<string, Advisory>();

  private versionKey(name: string, version: string): string {
    return `${name}@${version}`;
  }

  async getPublisher(id: string): Promise<Publisher | null> {
    return this.publishers.get(id) ?? null;
  }

  async createPublisher(publisher: Publisher): Promise<void> {
    this.publishers.set(publisher.id, publisher);
  }

  async updatePublisher(id: string, updates: Partial<Publisher>): Promise<void> {
    const existing = this.publishers.get(id);
    if (existing) this.publishers.set(id, { ...existing, ...updates });
  }

  async getPublisherByApiKey(apiKeyHash: string): Promise<Publisher | null> {
    // Use timing-safe comparison to prevent timing attacks on API key hashes
    const inputBuf = Buffer.from(apiKeyHash, 'utf8');

    for (const p of this.publishers.values()) {
      if (!p.apiKeyHash) continue;
      const storedBuf = Buffer.from(p.apiKeyHash, 'utf8');
      // timingSafeEqual requires equal-length buffers, SHA-256 hex is always 64 chars
      if (inputBuf.length === storedBuf.length && timingSafeEqual(inputBuf, storedBuf)) {
        return p;
      }
    }
    return null;
  }

  async getSkill(name: string): Promise<Skill | null> {
    return this.skills.get(name) ?? null;
  }

  async getSkillVersion(name: string, version: string): Promise<SkillVersion | null> {
    return this.versions.get(this.versionKey(name, version)) ?? null;
  }

  async getSkillVersions(name: string): Promise<SkillVersion[]> {
    const result: SkillVersion[] = [];
    for (const [key, v] of this.versions) {
      if (key.startsWith(`${name}@`)) result.push(v);
    }
    return result;
  }

  async createSkill(skill: Skill): Promise<void> {
    this.skills.set(skill.name, skill);
  }

  async updateSkill(name: string, updates: Partial<Skill>): Promise<void> {
    const existing = this.skills.get(name);
    if (existing) this.skills.set(name, { ...existing, ...updates });
  }

  async createSkillVersion(version: SkillVersion): Promise<void> {
    this.versions.set(this.versionKey(version.skillId, version.version), version);
  }

  async updateSkillVersion(name: string, version: string, updates: Partial<SkillVersion>): Promise<void> {
    const key = this.versionKey(name, version);
    const existing = this.versions.get(key);
    if (existing) this.versions.set(key, { ...existing, ...updates });
  }

  async searchSkills(query: SearchQuery): Promise<SearchResult> {
    let results = [...this.skills.values()];

    if (query.q) {
      const q = query.q.toLowerCase();
      results = results.filter(s =>
        s.name.toLowerCase().includes(q) ||
        s.description?.toLowerCase().includes(q) ||
        s.author.toLowerCase().includes(q)
      );
    }

    if (query.type) {
      results = results.filter(s => s.type === query.type);
    }

    if (query.tier) {
      const publisherTiers = new Map<string, string>();
      for (const p of this.publishers.values()) publisherTiers.set(p.id, p.tier);
      results = results.filter(s => publisherTiers.get(s.publisherId) === query.tier);
    }

    const total = results.length;

    if (query.sort === 'downloads') results.sort((a, b) => b.downloads - a.downloads);
    else if (query.sort === 'trust_score') results.sort((a, b) => (b.trustScore ?? 0) - (a.trustScore ?? 0));
    else results.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));

    const offset = query.offset ?? 0;
    const limit = query.limit ?? 20;
    results = results.slice(offset, offset + limit);

    return { skills: results, total, limit, offset };
  }

  async getSubmission(id: string): Promise<Submission | null> {
    return this.submissions.get(id) ?? null;
  }

  async createSubmission(submission: Submission): Promise<void> {
    this.submissions.set(submission.id, submission);
  }

  async updateSubmission(id: string, updates: Partial<Submission>): Promise<void> {
    const existing = this.submissions.get(id);
    if (existing) this.submissions.set(id, { ...existing, ...updates });
  }

  async listSubmissions(publisherId: string): Promise<Submission[]> {
    return [...this.submissions.values()].filter(s => s.publisherId === publisherId);
  }

  async getAdvisory(id: string): Promise<Advisory | null> {
    return this.advisories.get(id) ?? null;
  }

  async listAdvisories(): Promise<Advisory[]> {
    return [...this.advisories.values()];
  }

  async createAdvisory(advisory: Advisory): Promise<void> {
    this.advisories.set(advisory.id, advisory);
  }
}
