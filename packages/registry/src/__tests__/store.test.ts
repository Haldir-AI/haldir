import { describe, it, expect, beforeEach } from 'vitest';
import { MemoryStore } from '../store/memory.js';
import type { Publisher, Skill, SkillVersion, Submission, Advisory } from '../types.js';

describe('MemoryStore', () => {
  let store: MemoryStore;

  beforeEach(() => {
    store = new MemoryStore();
  });

  describe('publishers', () => {
    const pub: Publisher = {
      id: 'pub-1',
      displayName: 'Test Publisher',
      tier: 'unverified',
      createdAt: '2025-01-01T00:00:00Z',
      totalApproved: 0,
      totalRejected: 0,
      totalRevoked: 0,
      apiKeyHash: 'hash123',
    };

    it('creates and retrieves publisher', async () => {
      await store.createPublisher(pub);
      const result = await store.getPublisher('pub-1');
      expect(result).toEqual(pub);
    });

    it('returns null for missing publisher', async () => {
      expect(await store.getPublisher('nope')).toBeNull();
    });

    it('updates publisher', async () => {
      await store.createPublisher(pub);
      await store.updatePublisher('pub-1', { totalApproved: 5 });
      const result = await store.getPublisher('pub-1');
      expect(result!.totalApproved).toBe(5);
    });

    it('finds publisher by API key hash', async () => {
      await store.createPublisher(pub);
      const result = await store.getPublisherByApiKey('hash123');
      expect(result!.id).toBe('pub-1');
    });

    it('returns null for unknown API key', async () => {
      expect(await store.getPublisherByApiKey('unknown')).toBeNull();
    });
  });

  describe('skills', () => {
    const skill: Skill = {
      id: 'my-skill',
      name: 'my-skill',
      type: 'skill.md',
      description: 'A test skill',
      author: 'tester',
      latestVersion: '1.0.0',
      createdAt: '2025-01-01T00:00:00Z',
      updatedAt: '2025-01-01T00:00:00Z',
      publisherId: 'pub-1',
      downloads: 0,
    };

    it('creates and retrieves skill', async () => {
      await store.createSkill(skill);
      const result = await store.getSkill('my-skill');
      expect(result).toEqual(skill);
    });

    it('returns null for missing skill', async () => {
      expect(await store.getSkill('nope')).toBeNull();
    });

    it('updates skill', async () => {
      await store.createSkill(skill);
      await store.updateSkill('my-skill', { downloads: 42 });
      const result = await store.getSkill('my-skill');
      expect(result!.downloads).toBe(42);
    });
  });

  describe('skill versions', () => {
    const sv: SkillVersion = {
      skillId: 'my-skill',
      version: '1.0.0',
      publishedAt: '2025-01-01T00:00:00Z',
      status: 'approved',
    };

    it('creates and retrieves version', async () => {
      await store.createSkillVersion(sv);
      const result = await store.getSkillVersion('my-skill', '1.0.0');
      expect(result).toEqual(sv);
    });

    it('returns null for missing version', async () => {
      expect(await store.getSkillVersion('my-skill', '9.9.9')).toBeNull();
    });

    it('lists versions for a skill', async () => {
      await store.createSkillVersion(sv);
      await store.createSkillVersion({ ...sv, version: '2.0.0' });
      const versions = await store.getSkillVersions('my-skill');
      expect(versions).toHaveLength(2);
    });

    it('updates version', async () => {
      await store.createSkillVersion(sv);
      await store.updateSkillVersion('my-skill', '1.0.0', { status: 'rejected' });
      const result = await store.getSkillVersion('my-skill', '1.0.0');
      expect(result!.status).toBe('rejected');
    });
  });

  describe('submissions', () => {
    const sub: Submission = {
      id: 'sub-1',
      skillName: 'my-skill',
      version: '1.0.0',
      type: 'skill.md',
      publisherId: 'pub-1',
      status: 'queued',
      createdAt: '2025-01-01T00:00:00Z',
      vettingPath: 'full',
    };

    it('creates and retrieves submission', async () => {
      await store.createSubmission(sub);
      const result = await store.getSubmission('sub-1');
      expect(result).toEqual(sub);
    });

    it('returns null for missing submission', async () => {
      expect(await store.getSubmission('nope')).toBeNull();
    });

    it('lists submissions by publisher', async () => {
      await store.createSubmission(sub);
      await store.createSubmission({ ...sub, id: 'sub-2', publisherId: 'pub-2' });
      const list = await store.listSubmissions('pub-1');
      expect(list).toHaveLength(1);
      expect(list[0].id).toBe('sub-1');
    });

    it('updates submission', async () => {
      await store.createSubmission(sub);
      await store.updateSubmission('sub-1', { status: 'approved' });
      const result = await store.getSubmission('sub-1');
      expect(result!.status).toBe('approved');
    });
  });

  describe('advisories', () => {
    const adv: Advisory = {
      id: 'ADV-1',
      skillName: 'bad-skill',
      severity: 'critical',
      title: 'Remote code execution',
      description: 'Allows arbitrary code execution',
      publishedAt: '2025-01-01T00:00:00Z',
      affectedVersions: ['1.0.0', '1.0.1'],
    };

    it('creates and retrieves advisory', async () => {
      await store.createAdvisory(adv);
      const result = await store.getAdvisory('ADV-1');
      expect(result).toEqual(adv);
    });

    it('returns null for missing advisory', async () => {
      expect(await store.getAdvisory('nope')).toBeNull();
    });

    it('lists all advisories', async () => {
      await store.createAdvisory(adv);
      await store.createAdvisory({ ...adv, id: 'ADV-2', skillName: 'another' });
      const list = await store.listAdvisories();
      expect(list).toHaveLength(2);
    });
  });

  describe('search', () => {
    beforeEach(async () => {
      await store.createPublisher({
        id: 'pub-1', displayName: 'P1', tier: 'verified',
        createdAt: '2025-01-01T00:00:00Z', totalApproved: 5, totalRejected: 0, totalRevoked: 0,
      });
      await store.createSkill({
        id: 'alpha', name: 'alpha', type: 'skill.md', description: 'Alpha skill',
        author: 'tester', latestVersion: '1.0.0', createdAt: '2025-01-01T00:00:00Z',
        updatedAt: '2025-06-01T00:00:00Z', publisherId: 'pub-1', downloads: 100,
        trustScore: 90,
      });
      await store.createSkill({
        id: 'beta', name: 'beta', type: 'mcp', description: 'Beta MCP server',
        author: 'tester', latestVersion: '2.0.0', createdAt: '2025-02-01T00:00:00Z',
        updatedAt: '2025-07-01T00:00:00Z', publisherId: 'pub-1', downloads: 50,
        trustScore: 80,
      });
    });

    it('returns all skills with empty query', async () => {
      const result = await store.searchSkills({});
      expect(result.total).toBe(2);
    });

    it('filters by text query', async () => {
      const result = await store.searchSkills({ q: 'alpha' });
      expect(result.total).toBe(1);
      expect(result.skills[0].name).toBe('alpha');
    });

    it('filters by type', async () => {
      const result = await store.searchSkills({ type: 'mcp' });
      expect(result.total).toBe(1);
      expect(result.skills[0].name).toBe('beta');
    });

    it('filters by tier', async () => {
      const result = await store.searchSkills({ tier: 'verified' });
      expect(result.total).toBe(2);
    });

    it('sorts by downloads', async () => {
      const result = await store.searchSkills({ sort: 'downloads' });
      expect(result.skills[0].name).toBe('alpha');
    });

    it('sorts by trust_score', async () => {
      const result = await store.searchSkills({ sort: 'trust_score' });
      expect(result.skills[0].name).toBe('alpha');
    });

    it('paginates with limit and offset', async () => {
      const result = await store.searchSkills({ limit: 1, offset: 1 });
      expect(result.skills).toHaveLength(1);
      expect(result.total).toBe(2);
    });
  });

  describe('pattern bundles', () => {
    it('adds and retrieves a bundle', async () => {
      const bundle = {
        version: '1.0.0',
        releasedAt: '2026-02-14T00:00:00Z',
        patternCount: 2,
        patterns: [
          { id: 'p1', category: 'exfiltration' as const, severity: 'high' as const, name: 'P1', description: 'D1', regex: { source: 'foo', flags: '' }, fileExtensions: ['js'] },
          { id: 'p2', category: 'obfuscation' as const, severity: 'medium' as const, name: 'P2', description: 'D2', regex: { source: 'bar', flags: 'i' }, fileExtensions: ['ts'] },
        ],
      };
      await store.addPatternBundle(bundle);
      const result = await store.getPatternBundle('1.0.0');
      expect(result).toEqual(bundle);
    });

    it('returns null for unknown version', async () => {
      const result = await store.getPatternBundle('9.9.9');
      expect(result).toBeNull();
    });

    it('getLatest returns null when empty', async () => {
      const result = await store.getLatestPatternBundle();
      expect(result).toBeNull();
    });

    it('getLatest returns most recent by releasedAt', async () => {
      await store.addPatternBundle({ version: '1.0.0', releasedAt: '2026-01-01T00:00:00Z', patternCount: 0, patterns: [] });
      await store.addPatternBundle({ version: '2.0.0', releasedAt: '2026-02-01T00:00:00Z', patternCount: 0, patterns: [] });
      await store.addPatternBundle({ version: '1.5.0', releasedAt: '2026-01-15T00:00:00Z', patternCount: 0, patterns: [] });
      const latest = await store.getLatestPatternBundle();
      expect(latest?.version).toBe('2.0.0');
    });

    it('listVersions returns all added versions', async () => {
      await store.addPatternBundle({ version: '1.0.0', releasedAt: '2026-01-01T00:00:00Z', patternCount: 0, patterns: [] });
      await store.addPatternBundle({ version: '2.0.0', releasedAt: '2026-02-01T00:00:00Z', patternCount: 0, patterns: [] });
      const versions = await store.listPatternVersions();
      expect(versions).toContain('1.0.0');
      expect(versions).toContain('2.0.0');
      expect(versions).toHaveLength(2);
    });
  });
});
