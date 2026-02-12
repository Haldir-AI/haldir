import { Router } from 'express';
import type { RegistryStore } from '../store/types.js';

export function revocationsRouter(store: RegistryStore): Router {
  const router = Router();

  router.post('/', async (req, res) => {
    if (!req.auth) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    const body = req.body;
    if (!body || typeof body !== 'object') {
      res.status(400).json({ error: 'Request body must be a JSON object' });
      return;
    }

    const { skillName, version, reason } = body as {
      skillName?: string;
      version?: string;
      reason?: string;
    };

    if (!skillName || !version) {
      res.status(400).json({ error: 'Missing required fields: skillName, version' });
      return;
    }

    const skill = await store.getSkill(skillName);
    if (!skill) {
      res.status(404).json({ error: 'Skill not found' });
      return;
    }

    if (skill.publisherId !== req.auth.publisher.id) {
      res.status(403).json({ error: 'Only the publisher can revoke a skill version' });
      return;
    }

    const sv = await store.getSkillVersion(skillName, version);
    if (!sv) {
      res.status(404).json({ error: 'Version not found' });
      return;
    }

    await store.updateSkillVersion(skillName, version, { status: 'rejected' });

    const publisher = req.auth.publisher;
    await store.updatePublisher(publisher.id, {
      totalRevoked: publisher.totalRevoked + 1,
    });

    res.json({
      revoked: true,
      skill: skillName,
      version,
      reason: reason ?? 'Publisher-initiated revocation',
    });
  });

  return router;
}
