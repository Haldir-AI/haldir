import { Router } from 'express';
import { randomBytes } from 'node:crypto';
import type { RegistryStore } from '../store/types.js';
import type { Advisory } from '../types.js';

export function advisoriesRouter(store: RegistryStore): Router {
  const router = Router();

  router.get('/', async (_req, res) => {
    const advisories = await store.listAdvisories();
    res.json({ advisories });
  });

  router.get('/:id', async (req, res) => {
    const advisory = await store.getAdvisory(req.params.id);
    if (!advisory) {
      res.status(404).json({ error: 'Advisory not found' });
      return;
    }
    res.json(advisory);
  });

  router.post('/', async (req, res) => {
    if (!req.auth) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    if (req.auth.publisher.tier !== 'hydracore') {
      res.status(403).json({ error: 'Only hydracore-tier publishers can create advisories' });
      return;
    }

    const body = req.body;
    if (!body || typeof body !== 'object') {
      res.status(400).json({ error: 'Request body must be a JSON object' });
      return;
    }

    const { skillName, severity, title, description, affectedVersions } = body as Partial<Advisory>;

    if (!skillName || !severity || !title || !description || !affectedVersions?.length) {
      res.status(400).json({ error: 'Missing required fields: skillName, severity, title, description, affectedVersions' });
      return;
    }

    const validSeverities = ['critical', 'high', 'medium', 'low'];
    if (!validSeverities.includes(severity)) {
      res.status(400).json({ error: `Invalid severity: must be one of ${validSeverities.join(', ')}` });
      return;
    }

    const id = `ADV-${Date.now()}-${randomBytes(4).toString('hex')}`;
    const advisory: Advisory = {
      id,
      skillName,
      severity,
      title,
      description,
      publishedAt: new Date().toISOString(),
      affectedVersions,
    };

    await store.createAdvisory(advisory);
    res.status(201).json(advisory);
  });

  return router;
}
