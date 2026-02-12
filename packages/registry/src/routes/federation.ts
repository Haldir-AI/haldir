import { Router } from 'express';
import type { RegistryStore } from '../store/types.js';
import { computeTier } from '../tiers.js';

export function federationRouter(store: RegistryStore): Router {
  const router = Router();

  router.get('/badge/:name', async (req, res) => {
    const skill = await store.getSkill(req.params.name);
    if (!skill) {
      res.json({ verified: false, reason: 'Skill not found in registry' });
      return;
    }

    const publisher = await store.getPublisher(skill.publisherId);
    const tier = publisher ? computeTier(publisher) : 'unverified';

    const latestVersion = await store.getSkillVersion(skill.name, skill.latestVersion);
    const approved = latestVersion?.status === 'approved';

    res.json({
      verified: approved,
      skill: skill.name,
      version: skill.latestVersion,
      tier,
      trustScore: skill.trustScore ?? null,
      badge: approved ? getBadgeUrl(tier) : null,
    });
  });

  router.get('/badge/:name/:version', async (req, res) => {
    const { name, version } = req.params;
    const sv = await store.getSkillVersion(name, version);
    if (!sv) {
      res.json({ verified: false, reason: 'Version not found' });
      return;
    }

    const skill = await store.getSkill(name);
    const publisher = skill ? await store.getPublisher(skill.publisherId) : null;
    const tier = publisher ? computeTier(publisher) : 'unverified';

    res.json({
      verified: sv.status === 'approved',
      skill: name,
      version,
      tier,
      trustScore: sv.trustScore ?? null,
      badge: sv.status === 'approved' ? getBadgeUrl(tier) : null,
    });
  });

  router.get('/verify/:name/:version', async (req, res) => {
    const { name, version } = req.params;
    const sv = await store.getSkillVersion(name, version);
    if (!sv) {
      res.status(404).json({ error: 'Version not found' });
      return;
    }

    const skill = await store.getSkill(name);
    const publisher = skill ? await store.getPublisher(skill.publisherId) : null;
    const tier = publisher ? computeTier(publisher) : 'unverified';

    res.json({
      name,
      version,
      status: sv.status,
      tier,
      trustScore: sv.trustScore ?? null,
      publishedAt: sv.publishedAt,
      vettingResults: sv.vettingResults ?? null,
      publisher: publisher ? {
        id: publisher.id,
        displayName: publisher.displayName,
        tier,
      } : null,
    });
  });

  return router;
}

function getBadgeUrl(tier: string): string {
  return `https://haldir.ai/badges/${tier}.svg`;
}
