import { Router } from 'express';
import type { RegistryStore } from '../store/types.js';

export function patternsRouter(store: RegistryStore): Router {
  const router = Router();

  router.get('/versions', async (_req, res) => {
    const versions = await store.listPatternVersions();
    res.json({ versions });
  });

  router.get('/:version', async (req, res) => {
    const bundle = await store.getPatternBundle(req.params.version);
    if (!bundle) {
      res.status(404).json({ error: `Pattern version ${req.params.version} not found` });
      return;
    }
    res.json(bundle);
  });

  router.get('/', async (_req, res) => {
    const bundle = await store.getLatestPatternBundle();
    if (!bundle) {
      res.status(404).json({ error: 'No pattern bundles available' });
      return;
    }
    res.json(bundle);
  });

  return router;
}
