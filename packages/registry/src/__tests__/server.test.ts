import { describe, it, expect, beforeEach } from 'vitest';
import { createServer } from '../server.js';
import { MemoryStore } from '../store/memory.js';
import { hashApiKey } from '../auth/middleware.js';
import type { Publisher } from '../types.js';

function makeRequest(app: ReturnType<typeof createServer>, method: string, path: string, body?: unknown, token?: string) {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  return new Promise<{ status: number; body: Record<string, unknown> }>((resolve) => {
    const server = app.listen(0, () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      const url = `http://127.0.0.1:${port}${path}`;

      fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
      })
        .then(async (res) => {
          const json = await res.json().catch(() => ({}));
          server.close();
          resolve({ status: res.status, body: json as Record<string, unknown> });
        })
        .catch(() => {
          server.close();
          resolve({ status: 500, body: {} });
        });
    });
  });
}

const API_KEY = 'test-api-key-12345';

describe('Registry Server', () => {
  let store: MemoryStore;
  let app: ReturnType<typeof createServer>;
  let publisher: Publisher;

  beforeEach(async () => {
    store = new MemoryStore();
    app = createServer({ store });
    publisher = {
      id: 'pub-1',
      displayName: 'Test Publisher',
      tier: 'unverified',
      createdAt: '2025-01-01T00:00:00Z',
      totalApproved: 0,
      totalRejected: 0,
      totalRevoked: 0,
      apiKeyHash: hashApiKey(API_KEY),
    };
    await store.createPublisher(publisher);
  });

  describe('GET /health', () => {
    it('returns ok', async () => {
      const res = await makeRequest(app, 'GET', '/health');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('ok');
    });
  });

  describe('GET /v1/search', () => {
    it('returns empty results', async () => {
      const res = await makeRequest(app, 'GET', '/v1/search');
      expect(res.status).toBe(200);
      expect(res.body.total).toBe(0);
    });

    it('finds skills by query', async () => {
      await store.createSkill({
        id: 'test-skill', name: 'test-skill', type: 'skill.md',
        description: 'A cool skill', author: 'tester', latestVersion: '1.0.0',
        createdAt: '2025-01-01T00:00:00Z', updatedAt: '2025-01-01T00:00:00Z',
        publisherId: 'pub-1', downloads: 0,
      });
      const res = await makeRequest(app, 'GET', '/v1/search?q=cool');
      expect(res.status).toBe(200);
      expect(res.body.total).toBe(1);
    });
  });

  describe('GET /v1/skills/:name', () => {
    it('returns 404 for unknown skill', async () => {
      const res = await makeRequest(app, 'GET', '/v1/skills/unknown');
      expect(res.status).toBe(404);
    });

    it('returns skill with versions', async () => {
      await store.createSkill({
        id: 'my-skill', name: 'my-skill', type: 'skill.md',
        author: 'tester', latestVersion: '1.0.0',
        createdAt: '2025-01-01T00:00:00Z', updatedAt: '2025-01-01T00:00:00Z',
        publisherId: 'pub-1', downloads: 0,
      });
      await store.createSkillVersion({
        skillId: 'my-skill', version: '1.0.0',
        publishedAt: '2025-01-01T00:00:00Z', status: 'approved',
      });

      const res = await makeRequest(app, 'GET', '/v1/skills/my-skill');
      expect(res.status).toBe(200);
      expect(res.body.name).toBe('my-skill');
      expect((res.body.versions as unknown[]).length).toBe(1);
    });
  });

  describe('GET /v1/skills/:name/:version', () => {
    it('returns 404 for unknown version', async () => {
      const res = await makeRequest(app, 'GET', '/v1/skills/my-skill/9.9.9');
      expect(res.status).toBe(404);
    });
  });

  describe('POST /v1/submit', () => {
    it('rejects without auth', async () => {
      const res = await makeRequest(app, 'POST', '/v1/submit', {
        name: 'test', version: '1.0.0', type: 'skill.md',
      });
      expect(res.status).toBe(401);
    });

    it('rejects missing fields', async () => {
      const res = await makeRequest(app, 'POST', '/v1/submit', { name: 'test' }, API_KEY);
      expect(res.status).toBe(400);
    });

    it('creates submission', async () => {
      const res = await makeRequest(app, 'POST', '/v1/submit', {
        name: 'new-skill', version: '1.0.0', type: 'skill.md', description: 'Test',
      }, API_KEY);
      expect(res.status).toBe(202);
      expect(res.body.status).toBe('queued');
      expect(res.body.submission_id).toBeDefined();
    });

    it('rejects duplicate version', async () => {
      await store.createSkillVersion({
        skillId: 'dup-skill', version: '1.0.0',
        publishedAt: '2025-01-01T00:00:00Z', status: 'approved',
      });
      const res = await makeRequest(app, 'POST', '/v1/submit', {
        name: 'dup-skill', version: '1.0.0', type: 'skill.md',
      }, API_KEY);
      expect(res.status).toBe(409);
    });
  });

  describe('GET /v1/submit/status/:id', () => {
    it('returns 404 for unknown submission', async () => {
      const res = await makeRequest(app, 'GET', '/v1/submit/status/nope', undefined, API_KEY);
      expect(res.status).toBe(404);
    });
  });

  describe('GET /v1/publishers/:id', () => {
    it('returns publisher profile', async () => {
      const res = await makeRequest(app, 'GET', '/v1/publishers/pub-1');
      expect(res.status).toBe(200);
      expect(res.body.displayName).toBe('Test Publisher');
      expect(res.body.apiKeyHash).toBeUndefined();
    });

    it('returns 404 for unknown publisher', async () => {
      const res = await makeRequest(app, 'GET', '/v1/publishers/unknown');
      expect(res.status).toBe(404);
    });
  });

  describe('POST /v1/revocations', () => {
    beforeEach(async () => {
      await store.createSkill({
        id: 'revoke-skill', name: 'revoke-skill', type: 'skill.md',
        author: 'tester', latestVersion: '1.0.0',
        createdAt: '2025-01-01T00:00:00Z', updatedAt: '2025-01-01T00:00:00Z',
        publisherId: 'pub-1', downloads: 0,
      });
      await store.createSkillVersion({
        skillId: 'revoke-skill', version: '1.0.0',
        publishedAt: '2025-01-01T00:00:00Z', status: 'approved',
      });
    });

    it('rejects without auth', async () => {
      const res = await makeRequest(app, 'POST', '/v1/revocations', {
        skillName: 'revoke-skill', version: '1.0.0',
      });
      expect(res.status).toBe(401);
    });

    it('revokes a version', async () => {
      const res = await makeRequest(app, 'POST', '/v1/revocations', {
        skillName: 'revoke-skill', version: '1.0.0', reason: 'Security issue',
      }, API_KEY);
      expect(res.status).toBe(200);
      expect(res.body.revoked).toBe(true);

      const sv = await store.getSkillVersion('revoke-skill', '1.0.0');
      expect(sv!.status).toBe('rejected');
    });

    it('rejects revocation of another publisher skill', async () => {
      await store.createSkill({
        id: 'other-skill', name: 'other-skill', type: 'skill.md',
        author: 'other', latestVersion: '1.0.0',
        createdAt: '2025-01-01T00:00:00Z', updatedAt: '2025-01-01T00:00:00Z',
        publisherId: 'pub-other', downloads: 0,
      });
      const res = await makeRequest(app, 'POST', '/v1/revocations', {
        skillName: 'other-skill', version: '1.0.0',
      }, API_KEY);
      expect(res.status).toBe(403);
    });
  });

  describe('advisories', () => {
    it('lists empty advisories', async () => {
      const res = await makeRequest(app, 'GET', '/v1/advisories');
      expect(res.status).toBe(200);
      expect((res.body.advisories as unknown[]).length).toBe(0);
    });

    it('rejects advisory creation from non-hydracore publisher', async () => {
      const res = await makeRequest(app, 'POST', '/v1/advisories', {
        skillName: 'bad', severity: 'critical', title: 'RCE',
        description: 'Bad', affectedVersions: ['1.0.0'],
      }, API_KEY);
      expect(res.status).toBe(403);
    });

    it('allows hydracore publisher to create advisory', async () => {
      await store.updatePublisher('pub-1', { tier: 'hydracore' });
      const res = await makeRequest(app, 'POST', '/v1/advisories', {
        skillName: 'bad-skill', severity: 'high', title: 'Data leak',
        description: 'Leaks env vars', affectedVersions: ['1.0.0'],
      }, API_KEY);
      expect(res.status).toBe(201);
      expect(res.body.id).toBeDefined();
    });
  });

  describe('GET /.well-known/haldir-revocations', () => {
    it('returns revocation list', async () => {
      await store.createAdvisory({
        id: 'ADV-1', skillName: 'bad', severity: 'critical',
        title: 'RCE', description: 'Bad stuff', publishedAt: '2025-01-01T00:00:00Z',
        affectedVersions: ['1.0.0'],
      });

      const res = await makeRequest(app, 'GET', '/.well-known/haldir-revocations');
      expect(res.status).toBe(200);
      expect(res.body.schema_version).toBe('1.0');
      expect((res.body.entries as unknown[]).length).toBe(1);
    });
  });

  describe('federation', () => {
    beforeEach(async () => {
      await store.createSkill({
        id: 'fed-skill', name: 'fed-skill', type: 'skill.md',
        author: 'tester', latestVersion: '1.0.0',
        createdAt: '2025-01-01T00:00:00Z', updatedAt: '2025-01-01T00:00:00Z',
        publisherId: 'pub-1', downloads: 100, trustScore: 85,
      });
      await store.createSkillVersion({
        skillId: 'fed-skill', version: '1.0.0',
        publishedAt: '2025-01-01T00:00:00Z', status: 'approved', trustScore: 85,
      });
    });

    it('GET /v1/federation/badge/:name returns badge for approved skill', async () => {
      const res = await makeRequest(app, 'GET', '/v1/federation/badge/fed-skill');
      expect(res.status).toBe(200);
      expect(res.body.verified).toBe(true);
      expect(res.body.trustScore).toBe(85);
      expect(res.body.badge).toContain('haldir.ai/badges');
    });

    it('GET /v1/federation/badge/:name returns unverified for unknown skill', async () => {
      const res = await makeRequest(app, 'GET', '/v1/federation/badge/unknown');
      expect(res.status).toBe(200);
      expect(res.body.verified).toBe(false);
    });

    it('GET /v1/federation/badge/:name/:version returns badge for specific version', async () => {
      const res = await makeRequest(app, 'GET', '/v1/federation/badge/fed-skill/1.0.0');
      expect(res.status).toBe(200);
      expect(res.body.verified).toBe(true);
      expect(res.body.version).toBe('1.0.0');
    });

    it('GET /v1/federation/verify/:name/:version returns full verification details', async () => {
      const res = await makeRequest(app, 'GET', '/v1/federation/verify/fed-skill/1.0.0');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('approved');
      expect(res.body.publisher).toBeDefined();
      expect((res.body.publisher as Record<string, unknown>).displayName).toBe('Test Publisher');
    });

    it('GET /v1/federation/verify/:name/:version returns 404 for unknown', async () => {
      const res = await makeRequest(app, 'GET', '/v1/federation/verify/unknown/1.0.0');
      expect(res.status).toBe(404);
    });
  });
});
