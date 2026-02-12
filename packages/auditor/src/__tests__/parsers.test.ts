import { describe, it, expect } from 'vitest';
import { parsePackageJson, analyzePackageLockDepth, analyzePnpmLockDepth, hasLockfile } from '../parsers/package-json.js';
import { parseRequirementsTxt, hasRequirementsHash } from '../parsers/requirements-txt.js';
import { parsePyprojectToml, extractPep723 } from '../parsers/pyproject-toml.js';

describe('parsePackageJson', () => {
  it('parses dependencies', () => {
    const deps = parsePackageJson(JSON.stringify({
      dependencies: { express: '^4.18.0', zod: '3.22.4' },
    }));
    expect(deps).toHaveLength(2);
    expect(deps[0]).toMatchObject({ name: 'express', pinned: false });
    expect(deps[1]).toMatchObject({ name: 'zod', pinned: true });
  });

  it('parses peer and optional dependencies', () => {
    const deps = parsePackageJson(JSON.stringify({
      peerDependencies: { react: '>=18.0.0' },
      optionalDependencies: { fsevents: '2.3.3' },
    }));
    expect(deps).toHaveLength(2);
    expect(deps[0]).toMatchObject({ name: 'react', pinned: false });
    expect(deps[1]).toMatchObject({ name: 'fsevents', pinned: true });
  });

  it('ignores devDependencies', () => {
    const deps = parsePackageJson(JSON.stringify({
      devDependencies: { vitest: '^3.0.0' },
    }));
    expect(deps).toHaveLength(0);
  });

  it('marks workspace: as pinned', () => {
    const deps = parsePackageJson(JSON.stringify({
      dependencies: { '@haldir/core': 'workspace:*' },
    }));
    expect(deps[0].pinned).toBe(true);
  });

  it('marks file: as pinned', () => {
    const deps = parsePackageJson(JSON.stringify({
      dependencies: { local: 'file:../local' },
    }));
    expect(deps[0].pinned).toBe(true);
  });

  it('marks npm: alias with pinned version', () => {
    const deps = parsePackageJson(JSON.stringify({
      dependencies: { foo: 'npm:bar@1.2.3' },
    }));
    expect(deps[0].pinned).toBe(true);
  });

  it('marks ~ and ^ as unpinned', () => {
    const deps = parsePackageJson(JSON.stringify({
      dependencies: { a: '~1.0.0', b: '^2.0.0' },
    }));
    expect(deps[0].pinned).toBe(false);
    expect(deps[1].pinned).toBe(false);
  });

  it('returns empty for invalid JSON', () => {
    expect(parsePackageJson('not json')).toHaveLength(0);
  });

  it('returns empty for no deps sections', () => {
    expect(parsePackageJson(JSON.stringify({ name: 'foo' }))).toHaveLength(0);
  });
});

describe('hasLockfile', () => {
  it('detects package-lock.json', () => {
    expect(hasLockfile(['package.json', 'package-lock.json'])).toBe('package-lock.json');
  });

  it('detects pnpm-lock.yaml', () => {
    expect(hasLockfile(['package.json', 'pnpm-lock.yaml'])).toBe('pnpm-lock.yaml');
  });

  it('detects yarn.lock', () => {
    expect(hasLockfile(['package.json', 'yarn.lock'])).toBe('yarn.lock');
  });

  it('detects bun.lockb', () => {
    expect(hasLockfile(['package.json', 'bun.lockb'])).toBe('bun.lockb');
  });

  it('returns null when no lockfile', () => {
    expect(hasLockfile(['package.json', 'src'])).toBeNull();
  });
});

describe('analyzePackageLockDepth', () => {
  it('calculates depth from nested node_modules', () => {
    const lock = {
      packages: {
        '': {},
        'node_modules/a': {},
        'node_modules/a/node_modules/b': {},
        'node_modules/a/node_modules/b/node_modules/c': {},
      },
    };
    const result = analyzePackageLockDepth(JSON.stringify(lock));
    expect(result.maxDepth).toBe(3);
    expect(result.totalTransitive).toBe(3);
  });

  it('returns 0 for empty packages', () => {
    const result = analyzePackageLockDepth(JSON.stringify({ packages: {} }));
    expect(result.maxDepth).toBe(0);
  });

  it('handles invalid JSON', () => {
    const result = analyzePackageLockDepth('invalid');
    expect(result.maxDepth).toBe(0);
  });
});

describe('parseRequirementsTxt', () => {
  it('parses pinned deps', () => {
    const deps = parseRequirementsTxt('requests==2.31.0\nflask==3.0.0\n');
    expect(deps).toHaveLength(2);
    expect(deps[0]).toMatchObject({ name: 'requests', pinned: true });
    expect(deps[1]).toMatchObject({ name: 'flask', pinned: true });
  });

  it('detects unpinned deps', () => {
    const deps = parseRequirementsTxt('requests>=2.25.0\nflask\n');
    expect(deps[0].pinned).toBe(false);
    expect(deps[1].pinned).toBe(false);
  });

  it('detects hashes', () => {
    const deps = parseRequirementsTxt(
      'requests==2.31.0 --hash=sha256:abc123\nflask==3.0.0\n'
    );
    expect(deps[0].hasHash).toBe(true);
    expect(deps[1].hasHash).toBe(false);
  });

  it('skips comments and options', () => {
    const deps = parseRequirementsTxt('# comment\n-r other.txt\n--index-url x\nflask==3.0.0\n');
    expect(deps).toHaveLength(1);
    expect(deps[0].name).toBe('flask');
  });

  it('skips blank lines', () => {
    const deps = parseRequirementsTxt('\n\nflask==3.0.0\n\n');
    expect(deps).toHaveLength(1);
  });

  it('handles complex version specs', () => {
    const deps = parseRequirementsTxt('requests>=2.25.0,<3.0.0\n');
    expect(deps[0]).toMatchObject({ name: 'requests', pinned: false });
  });
});

describe('hasRequirementsHash', () => {
  it('returns true when hashes present', () => {
    expect(hasRequirementsHash('requests==2.31.0 --hash=sha256:abc\n')).toBe(true);
  });

  it('returns false when no hashes', () => {
    expect(hasRequirementsHash('requests==2.31.0\n')).toBe(false);
  });
});

describe('parsePyprojectToml', () => {
  it('parses dependencies array', () => {
    const content = `[project]
name = "my-skill"
dependencies = [
  "requests>=2.25.0",
  "flask==3.0.0",
]`;
    const deps = parsePyprojectToml(content);
    expect(deps.length).toBeGreaterThanOrEqual(2);
    const req = deps.find(d => d.name === 'requests');
    const fl = deps.find(d => d.name === 'flask');
    expect(req?.pinned).toBe(false);
    expect(fl?.pinned).toBe(true);
  });

  it('returns empty for no dependencies', () => {
    const deps = parsePyprojectToml('[project]\nname = "foo"\n');
    expect(deps).toHaveLength(0);
  });
});

describe('extractPep723', () => {
  it('extracts inline script dependencies', () => {
    const content = `# script dependencies
# requests>=2.25.0
# flask==3.0.0
`;
    const deps = extractPep723(content);
    expect(deps).toContain('requests>=2.25.0');
    expect(deps).toContain('flask==3.0.0');
  });

  it('returns empty for no PEP 723 marker', () => {
    const deps = extractPep723('import os\nprint("hello")\n');
    expect(deps).toHaveLength(0);
  });

  it('handles inline requires variant', () => {
    const content = `# inline requires
# httpx
`;
    const deps = extractPep723(content);
    expect(deps).toContain('httpx');
  });
});
