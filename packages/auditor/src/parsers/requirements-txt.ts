import type { Dependency } from '../types.js';

const PINNED_RE = /^==\d+/;
const HASH_RE = /--hash=/;
const COMMENT_RE = /^\s*(#|$)/;
const OPTION_RE = /^\s*-/;

export function parseRequirementsTxt(content: string): Dependency[] {
  const deps: Dependency[] = [];

  for (const rawLine of content.split('\n')) {
    const line = rawLine.trim();
    if (COMMENT_RE.test(line)) continue;
    if (OPTION_RE.test(line)) continue;
    if (line.length === 0) continue;

    const hasHash = HASH_RE.test(line);
    const cleaned = line.replace(/\s*\\$/, '').replace(/\s*--hash=\S+/g, '').trim();

    const match = cleaned.match(/^([a-zA-Z0-9_.-]+)\s*([><=!~]+\s*\S+(?:\s*,\s*[><=!~]+\s*\S+)*)?/);
    if (!match) continue;

    const name = match[1];
    const versionSpec = (match[2] ?? '').trim();
    const pinned = versionSpec.startsWith('==') && /^==\d+\.\d+/.test(versionSpec);

    deps.push({
      name,
      version: versionSpec || '*',
      pinned,
      hasHash,
      source: 'requirements.txt',
    });
  }

  return deps;
}

export function hasRequirementsHash(content: string): boolean {
  for (const line of content.split('\n')) {
    if (HASH_RE.test(line)) return true;
  }
  return false;
}
