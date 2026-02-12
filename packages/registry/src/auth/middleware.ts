import { createHash } from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import type { RegistryStore } from '../store/types.js';
import type { AuthContext } from './types.js';

declare global {
  namespace Express {
    interface Request {
      auth?: AuthContext;
    }
  }
}

export function hashApiKey(key: string): string {
  return createHash('sha256').update(key).digest('hex');
}

export function createAuthMiddleware(store: RegistryStore) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Missing or invalid Authorization header' });
      return;
    }

    const token = authHeader.slice(7);
    const keyHash = hashApiKey(token);
    const publisher = await store.getPublisherByApiKey(keyHash);

    if (!publisher) {
      res.status(401).json({ error: 'Invalid API key' });
      return;
    }

    req.auth = { publisher };
    next();
  };
}

export function createOptionalAuthMiddleware(store: RegistryStore) {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Bearer ')) {
      const token = authHeader.slice(7);
      const keyHash = hashApiKey(token);
      const publisher = await store.getPublisherByApiKey(keyHash);
      if (publisher) req.auth = { publisher };
    }
    next();
  };
}
