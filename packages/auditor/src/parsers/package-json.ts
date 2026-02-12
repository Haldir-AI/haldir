import type { Dependency } from '../types.js';

const PINNED_RE = /^\d+\.\d+\.\d+$/;
const EXACT_PROTOCOLS = ['file:', 'link:', 'workspace:'];

export function parsePackageJson(content: string): Dependency[] {
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(content);
  } catch {
    return [];
  }

  const deps: Dependency[] = [];
  const sections = ['dependencies', 'peerDependencies', 'optionalDependencies'] as const;

  for (const section of sections) {
    const map = pkg[section];
    if (!map || typeof map !== 'object') continue;
    for (const [name, version] of Object.entries(map as Record<string, string>)) {
      if (typeof version !== 'string') continue;
      deps.push({
        name,
        version,
        pinned: isPinned(version),
        hasHash: false,
        source: 'package.json',
      });
    }
  }

  return deps;
}

function isPinned(version: string): boolean {
  if (PINNED_RE.test(version)) return true;
  if (EXACT_PROTOCOLS.some(p => version.startsWith(p))) return true;
  if (version.startsWith('npm:') && PINNED_RE.test(version.split('@').pop() ?? '')) return true;
  return false;
}

export function hasLockfile(files: string[]): 'package-lock.json' | 'pnpm-lock.yaml' | 'yarn.lock' | 'bun.lockb' | null {
  const lockfiles = ['pnpm-lock.yaml', 'package-lock.json', 'yarn.lock', 'bun.lockb'] as const;
  for (const lf of lockfiles) {
    if (files.includes(lf)) return lf;
  }
  return null;
}

export interface PackageLockDepth {
  maxDepth: number;
  totalTransitive: number;
}

export function analyzePackageLockDepth(content: string): PackageLockDepth {
  let lock: Record<string, unknown>;
  try {
    lock = JSON.parse(content);
  } catch {
    return { maxDepth: 0, totalTransitive: 0 };
  }

  const packages = lock.packages as Record<string, unknown> | undefined;
  if (!packages || typeof packages !== 'object') {
    return { maxDepth: 0, totalTransitive: 0 };
  }

  let maxDepth = 0;
  let totalTransitive = 0;

  for (const key of Object.keys(packages)) {
    if (key === '') continue;
    const segments = key.split('node_modules/').length - 1;
    if (segments > maxDepth) maxDepth = segments;
    totalTransitive++;
  }

  return { maxDepth, totalTransitive };
}

export function analyzePnpmLockDepth(content: string): PackageLockDepth {
  const lines = content.split('\n');
  let maxDepth = 0;
  let totalTransitive = 0;
  let inPackages = false;

  for (const line of lines) {
    if (line.startsWith('packages:')) {
      inPackages = true;
      continue;
    }
    if (inPackages && /^\S/.test(line) && !line.startsWith(' ') && !line.startsWith('packages:')) {
      inPackages = false;
    }
    if (inPackages && line.trim().startsWith("'") && line.trim().endsWith("':")) {
      totalTransitive++;
      const depPath = line.trim().replace(/^'|':$/g, '');
      const depth = depPath.split('/').filter(s => !s.startsWith('@')).length;
      if (depth > maxDepth) maxDepth = depth;
    }
  }

  return { maxDepth: Math.min(maxDepth, 10), totalTransitive };
}
