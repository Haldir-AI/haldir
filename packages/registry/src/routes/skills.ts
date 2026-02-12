import { Router } from 'express';
import type { RegistryStore } from '../store/types.js';

export function skillsRouter(store: RegistryStore): Router {
  const router = Router();

  router.get('/:name', async (req, res) => {
    const skill = await store.getSkill(req.params.name);
    if (!skill) {
      res.status(404).json({ error: 'Skill not found' });
      return;
    }
    const versions = await store.getSkillVersions(skill.name);
    res.json({ ...skill, versions });
  });

  router.get('/:name/:version', async (req, res) => {
    const version = await store.getSkillVersion(req.params.name, req.params.version);
    if (!version) {
      res.status(404).json({ error: 'Version not found' });
      return;
    }
    res.json(version);
  });

  return router;
}
