import { Router } from 'express';
import type { RegistryStore } from '../store/types.js';
import type { SkillType, PublisherTier } from '../types.js';

export function searchRouter(store: RegistryStore): Router {
  const router = Router();

  router.get('/', async (req, res) => {
    const q = req.query.q as string | undefined;
    const type = req.query.type as SkillType | undefined;
    const tier = req.query.tier as PublisherTier | undefined;
    const sort = req.query.sort as 'downloads' | 'trust_score' | 'recently_updated' | undefined;
    const rawLimit = req.query.limit ? parseInt(req.query.limit as string, 10) : 20;
    const rawOffset = req.query.offset ? parseInt(req.query.offset as string, 10) : 0;
    const limit = Math.max(1, Math.min(100, isNaN(rawLimit) ? 20 : rawLimit));
    const offset = Math.max(0, isNaN(rawOffset) ? 0 : rawOffset);

    const result = await store.searchSkills({ q, type, tier, sort, limit, offset });
    res.json(result);
  });

  return router;
}
