import { describe, it, expect } from 'vitest';
import { checkPinning, checkHashes } from '../checks/pinning.js';
import { checkLockfile } from '../checks/lockfile.js';
import { checkDependencyCount } from '../checks/count.js';
import { checkDepth } from '../checks/depth.js';
import { checkSuspiciousPackages, checkInstallScripts } from '../checks/suspicious.js';
import { checkPep723Scripts } from '../checks/pep723.js';
import type { Dependency } from '../types.js';

const dep = (overrides: Partial<Dependency> = {}): Dependency => ({
  name: 'test-pkg',
  version: '1.0.0',
  pinned: true,
  hasHash: false,
  source: 'package.json',
  ...overrides,
});

describe('checkPinning', () => {
  it('flags unpinned dependencies', () => {
    const findings = checkPinning([
      dep({ name: 'a', version: '^1.0.0', pinned: false }),
      dep({ name: 'b', version: '1.0.0', pinned: true }),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].dependency).toBe('a');
    expect(findings[0].severity).toBe('high');
  });

  it('returns empty for all pinned', () => {
    expect(checkPinning([dep(), dep({ name: 'b' })])).toHaveLength(0);
  });

  it('returns empty for no deps', () => {
    expect(checkPinning([])).toHaveLength(0);
  });
});

describe('checkHashes', () => {
  it('flags partial hashes in requirements.txt', () => {
    const findings = checkHashes([
      dep({ name: 'a', hasHash: true, source: 'requirements.txt' }),
      dep({ name: 'b', hasHash: false, source: 'requirements.txt' }),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].dependency).toBe('b');
    expect(findings[0].category).toBe('unpinned');
  });

  it('no findings when all have hashes', () => {
    const findings = checkHashes([
      dep({ hasHash: true, source: 'requirements.txt' }),
      dep({ name: 'b', hasHash: true, source: 'requirements.txt' }),
    ]);
    expect(findings).toHaveLength(0);
  });

  it('no findings when none have hashes', () => {
    const findings = checkHashes([
      dep({ source: 'requirements.txt' }),
      dep({ name: 'b', source: 'requirements.txt' }),
    ]);
    expect(findings).toHaveLength(0);
  });

  it('ignores non-requirements.txt deps', () => {
    expect(checkHashes([dep({ hasHash: false })])).toHaveLength(0);
  });
});

describe('checkLockfile', () => {
  it('flags missing Node.js lockfile', () => {
    const findings = checkLockfile(['package.json'], ['package.json', 'src']);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('no_lockfile_node');
  });

  it('no flag when package-lock.json exists', () => {
    const findings = checkLockfile(['package.json'], ['package.json', 'package-lock.json']);
    expect(findings).toHaveLength(0);
  });

  it('no flag when pnpm-lock.yaml exists', () => {
    const findings = checkLockfile(['package.json'], ['package.json', 'pnpm-lock.yaml']);
    expect(findings).toHaveLength(0);
  });

  it('flags missing Python lockfile for pyproject.toml', () => {
    const findings = checkLockfile(['pyproject.toml'], ['pyproject.toml']);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('no_lockfile_python');
  });

  it('no flag when requirements.txt is itself the manifest', () => {
    const findings = checkLockfile(['requirements.txt'], ['requirements.txt']);
    expect(findings).toHaveLength(0);
  });
});

describe('checkDependencyCount', () => {
  it('flags high count for skill.md', () => {
    const deps = Array.from({ length: 25 }, (_, i) => dep({ name: `pkg-${i}` }));
    const findings = checkDependencyCount(deps, 'skill.md');
    expect(findings).toHaveLength(1);
    expect(findings[0].category).toBe('high_count');
  });

  it('no flag under limit for skill.md', () => {
    const deps = Array.from({ length: 15 }, (_, i) => dep({ name: `pkg-${i}` }));
    expect(checkDependencyCount(deps, 'skill.md')).toHaveLength(0);
  });

  it('flags high count for mcp with default 50', () => {
    const deps = Array.from({ length: 55 }, (_, i) => dep({ name: `pkg-${i}` }));
    const findings = checkDependencyCount(deps, 'mcp');
    expect(findings).toHaveLength(1);
  });

  it('no flag under limit for mcp', () => {
    const deps = Array.from({ length: 30 }, (_, i) => dep({ name: `pkg-${i}` }));
    expect(checkDependencyCount(deps, 'mcp')).toHaveLength(0);
  });

  it('respects custom limits', () => {
    const deps = Array.from({ length: 5 }, (_, i) => dep({ name: `pkg-${i}` }));
    expect(checkDependencyCount(deps, 'skill.md', 3)).toHaveLength(1);
    expect(checkDependencyCount(deps, 'skill.md', 10)).toHaveLength(0);
  });
});

describe('checkDepth', () => {
  it('flags deep tree', () => {
    const findings = checkDepth({ maxDepth: 8, totalTransitive: 100 });
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('deep_dep_tree');
  });

  it('no flag within limit', () => {
    expect(checkDepth({ maxDepth: 3, totalTransitive: 20 })).toHaveLength(0);
  });

  it('returns empty for null', () => {
    expect(checkDepth(null)).toHaveLength(0);
  });

  it('respects custom limit', () => {
    expect(checkDepth({ maxDepth: 4, totalTransitive: 10 }, 3)).toHaveLength(1);
    expect(checkDepth({ maxDepth: 4, totalTransitive: 10 }, 5)).toHaveLength(0);
  });
});

describe('checkSuspiciousPackages', () => {
  it('flags wildcard versions', () => {
    const findings = checkSuspiciousPackages([dep({ version: '*', pinned: false })]);
    expect(findings.some(f => f.id === 'wildcard_version')).toBe(true);
  });

  it('flags latest', () => {
    const findings = checkSuspiciousPackages([dep({ version: 'latest', pinned: false })]);
    expect(findings.some(f => f.id === 'wildcard_version')).toBe(true);
  });

  it('flags git deps', () => {
    const findings = checkSuspiciousPackages([dep({ version: 'git+https://github.com/foo/bar.git' })]);
    expect(findings.some(f => f.id === 'git_dependency')).toBe(true);
  });

  it('flags github: protocol', () => {
    const findings = checkSuspiciousPackages([dep({ version: 'github:foo/bar' })]);
    expect(findings.some(f => f.id === 'git_dependency')).toBe(true);
  });

  it('flags short scopes', () => {
    const findings = checkSuspiciousPackages([dep({ name: '@x/foo' })]);
    expect(findings.some(f => f.id === 'suspicious_scope')).toBe(true);
  });

  it('no flag for normal deps', () => {
    expect(checkSuspiciousPackages([dep()])).toHaveLength(0);
  });
});

describe('checkInstallScripts', () => {
  it('flags preinstall hook', () => {
    const findings = checkInstallScripts(JSON.stringify({
      scripts: { preinstall: 'node setup.js' },
    }));
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('install_script');
  });

  it('flags postinstall hook', () => {
    const findings = checkInstallScripts(JSON.stringify({
      scripts: { postinstall: 'node build.js' },
    }));
    expect(findings).toHaveLength(1);
  });

  it('no flag for normal scripts', () => {
    const findings = checkInstallScripts(JSON.stringify({
      scripts: { build: 'tsc', test: 'vitest' },
    }));
    expect(findings).toHaveLength(0);
  });

  it('handles invalid JSON', () => {
    expect(checkInstallScripts('not json')).toHaveLength(0);
  });
});

describe('checkPep723Scripts', () => {
  it('flags PEP 723 inline deps', () => {
    const files = new Map<string, string>();
    files.set('main.py', `# script dependencies\n# requests\n# flask==3.0.0\n`);
    const findings = checkPep723Scripts(files);
    expect(findings.some(f => f.id === 'pep723_inline_deps')).toBe(true);
  });

  it('flags unpinned PEP 723 deps as critical', () => {
    const files = new Map<string, string>();
    files.set('main.py', `# script dependencies\n# requests\n`);
    const findings = checkPep723Scripts(files);
    expect(findings.some(f => f.id === 'pep723_unpinned' && f.severity === 'critical')).toBe(true);
  });

  it('no flag for non-python files', () => {
    const files = new Map<string, string>();
    files.set('main.js', `# script dependencies\n# requests\n`);
    expect(checkPep723Scripts(files)).toHaveLength(0);
  });

  it('no flag for normal python', () => {
    const files = new Map<string, string>();
    files.set('main.py', 'import os\nprint("hello")\n');
    expect(checkPep723Scripts(files)).toHaveLength(0);
  });
});
