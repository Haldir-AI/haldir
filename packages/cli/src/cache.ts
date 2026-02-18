import { readFile, writeFile, mkdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { PatternBundle } from '@haldir/scanner';

export const DEFAULT_CACHE_DIR = join(homedir(), '.haldir', 'cache');
export const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

let cacheDir = DEFAULT_CACHE_DIR;

export function setCacheDir(dir: string): void {
  cacheDir = dir;
}

function bundlePath(version: string): string {
  return join(cacheDir, `patterns-${version}.json`);
}

function latestPath(): string {
  return join(cacheDir, 'patterns-latest.json');
}

export async function getCachedBundle(version?: string): Promise<PatternBundle | null> {
  const path = version ? bundlePath(version) : latestPath();
  try {
    const st = await stat(path);
    if (Date.now() - st.mtimeMs > CACHE_TTL_MS) return null;
    const data = await readFile(path, 'utf8');
    return JSON.parse(data) as PatternBundle;
  } catch {
    return null;
  }
}

export async function getStaleCachedBundle(version?: string): Promise<PatternBundle | null> {
  const path = version ? bundlePath(version) : latestPath();
  try {
    const data = await readFile(path, 'utf8');
    return JSON.parse(data) as PatternBundle;
  } catch {
    return null;
  }
}

export async function cacheBundle(bundle: PatternBundle): Promise<void> {
  await mkdir(cacheDir, { recursive: true });
  const data = JSON.stringify(bundle);
  await writeFile(bundlePath(bundle.version), data, 'utf8');
  await writeFile(latestPath(), data, 'utf8');
}
