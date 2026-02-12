import { Router } from 'express';
import type { RegistryStore } from '../store/types.js';
import { computeTier } from '../tiers.js';

export function publishersRouter(store: RegistryStore): Router {
  const router = Router();

  router.get('/:id', async (req, res) => {
    const publisher = await store.getPublisher(req.params.id);
    if (!publisher) {
      res.status(404).json({ error: 'Publisher not found' });
      return;
    }

    const currentTier = computeTier(publisher);
    const { apiKeyHash, ...safePublisher } = publisher;

    res.json({
      ...safePublisher,
      tier: currentTier,
      badges: getBadges(currentTier),
    });
  });

  return router;
}

function getBadges(tier: string): string[] {
  switch (tier) {
    case 'verified': return ['verified'];
    case 'trusted': return ['trusted'];
    case 'hydracore': return ['hydracore'];
    default: return [];
  }
}
