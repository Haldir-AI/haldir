import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import type { RegistryStore } from './store/types.js';
import { createAuthMiddleware, createOptionalAuthMiddleware } from './auth/middleware.js';
import { skillsRouter } from './routes/skills.js';
import { submitRouter } from './routes/submit.js';
import { searchRouter } from './routes/search.js';
import { publishersRouter } from './routes/publishers.js';
import { revocationsRouter } from './routes/revocations.js';
import { advisoriesRouter } from './routes/advisories.js';
import { federationRouter } from './routes/federation.js';

export interface ServerConfig {
  store: RegistryStore;
  prefix?: string;
}

export function createServer(config: ServerConfig): express.Express {
  const { store, prefix = '/v1' } = config;
  const app = express();
  const auth = createAuthMiddleware(store);
  const optionalAuth = createOptionalAuthMiddleware(store);

  app.use(express.json({ limit: '1mb' }));

  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    next();
  });

  app.use(`${prefix}/skills`, skillsRouter(store));
  app.use(`${prefix}/search`, searchRouter(store));
  app.use(`${prefix}/publishers`, publishersRouter(store));
  app.use(`${prefix}/submit`, auth, submitRouter(store));
  app.use(`${prefix}/revocations`, auth, revocationsRouter(store));
  app.use(`${prefix}/advisories`, optionalAuth, advisoriesRouter(store));
  app.use(`${prefix}/federation`, federationRouter(store));

  app.get('/.well-known/haldir-revocations', async (_req, res) => {
    const advisories = await store.listAdvisories();
    const revoked: Array<{ skill: string; versions: string[] }> = [];

    for (const adv of advisories) {
      revoked.push({ skill: adv.skillName, versions: adv.affectedVersions });
    }

    res.json({
      schema_version: '1.0',
      updated_at: new Date().toISOString(),
      entries: revoked,
    });
  });

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok' });
  });

  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}
