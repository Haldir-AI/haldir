import { Router } from 'express';
import { randomBytes } from 'node:crypto';
import type { RegistryStore } from '../store/types.js';
import type { Submission, SkillType } from '../types.js';
import { getVettingPath, getSkipLayers } from '../tiers.js';

export function submitRouter(store: RegistryStore): Router {
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

    const { name, version, type, description } = body as {
      name?: string;
      version?: string;
      type?: SkillType;
      description?: string;
    };

    if (!name || !version || !type) {
      res.status(400).json({ error: 'Missing required fields: name, version, type' });
      return;
    }

    if (!/^[a-zA-Z0-9@/_-]{1,128}$/.test(name)) {
      res.status(400).json({ error: 'Invalid skill name: must be 1-128 alphanumeric characters, @, /, _, or -' });
      return;
    }

    if (!/^[a-zA-Z0-9._-]{1,64}$/.test(version)) {
      res.status(400).json({ error: 'Invalid version format' });
      return;
    }

    const existing = await store.getSkillVersion(name, version);
    if (existing) {
      res.status(409).json({ error: `${name}@${version} already exists` });
      return;
    }

    const publisher = req.auth.publisher;
    const existingSkill = await store.getSkill(name);
    if (existingSkill && existingSkill.publisherId !== publisher.id) {
      res.status(403).json({ error: 'Only the original publisher can submit new versions' });
      return;
    }
    const isUpdate = existingSkill !== null;
    const vettingPath = getVettingPath(publisher.tier, isUpdate);
    const skipLayers = getSkipLayers(publisher.tier, isUpdate);

    const submissionId = `sub-${Date.now()}-${randomBytes(4).toString('hex')}`;
    const now = new Date().toISOString();

    const submission: Submission = {
      id: submissionId,
      skillName: name,
      version,
      type,
      publisherId: publisher.id,
      status: 'queued',
      createdAt: now,
      vettingPath,
    };

    await store.createSubmission(submission);

    let skill = await store.getSkill(name);
    if (!skill) {
      await store.createSkill({
        id: name,
        name,
        type,
        description,
        author: publisher.displayName,
        latestVersion: version,
        createdAt: now,
        updatedAt: now,
        publisherId: publisher.id,
        downloads: 0,
      });
    }

    await store.createSkillVersion({
      skillId: name,
      version,
      publishedAt: now,
      status: 'queued',
    });

    res.status(202).json({
      submission_id: submissionId,
      status: 'queued',
      vetting_path: vettingPath,
      skip_layers: skipLayers,
      skill: { name, version, type },
    });
  });

  router.get('/status/:id', async (req, res) => {
    const submission = await store.getSubmission(req.params.id);
    if (!submission) {
      res.status(404).json({ error: 'Submission not found' });
      return;
    }
    res.json(submission);
  });

  return router;
}
