import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { auditDirectory } from '../engine.js';

describe('auditDirectory', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'haldir-audit-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('returns pass for clean pinned package.json with lockfile', async () => {
    await writeFile(join(tempDir, 'SKILL.md'), '# My Skill\n');
    await writeFile(join(tempDir, 'package.json'), JSON.stringify({
      dependencies: { express: '4.18.2' },
    }));
    await writeFile(join(tempDir, 'package-lock.json'), JSON.stringify({
      packages: { '': {}, 'node_modules/express': {} },
    }));

    const result = await auditDirectory(tempDir, { checkCves: false });
    expect(result.status).toBe('pass');
    expect(result.dependencies_count).toBe(1);
    expect(result.lockfile_present).toBe(true);
    expect(result.manifests_found).toContain('package.json');
  });

  it('flags unpinned dependencies', async () => {
    await writeFile(join(tempDir, 'package.json'), JSON.stringify({
      dependencies: { express: '^4.18.0', zod: '~3.22.0' },
    }));
    await writeFile(join(tempDir, 'package-lock.json'), JSON.stringify({ packages: { '': {} } }));

    const result = await auditDirectory(tempDir, { checkCves: false });
    expect(result.status).toBe('flag');
    expect(result.findings.some(f => f.category === 'unpinned')).toBe(true);
  });

  it('flags missing lockfile', async () => {
    await writeFile(join(tempDir, 'package.json'), JSON.stringify({
      dependencies: { express: '4.18.2' },
    }));

    const result = await auditDirectory(tempDir, { checkCves: false });
    expect(result.findings.some(f => f.id === 'no_lockfile_node')).toBe(true);
  });

  it('flags high dependency count for skill.md', async () => {
    await writeFile(join(tempDir, 'SKILL.md'), '# My Skill\n');
    const deps: Record<string, string> = {};
    for (let i = 0; i < 25; i++) deps[`pkg-${i}`] = '1.0.0';
    await writeFile(join(tempDir, 'package.json'), JSON.stringify({ dependencies: deps }));
    await writeFile(join(tempDir, 'package-lock.json'), JSON.stringify({ packages: { '': {} } }));

    const result = await auditDirectory(tempDir, { checkCves: false });
    expect(result.findings.some(f => f.category === 'high_count')).toBe(true);
  });

  it('uses mcp limit when no SKILL.md', async () => {
    const deps: Record<string, string> = {};
    for (let i = 0; i < 25; i++) deps[`pkg-${i}`] = '1.0.0';
    await writeFile(join(tempDir, 'package.json'), JSON.stringify({ dependencies: deps }));
    await writeFile(join(tempDir, 'package-lock.json'), JSON.stringify({ packages: { '': {} } }));

    const result = await auditDirectory(tempDir, { checkCves: false });
    expect(result.findings.some(f => f.category === 'high_count')).toBe(false);
  });

  it('flags deep dependency tree', async () => {
    await writeFile(join(tempDir, 'package.json'), JSON.stringify({
      dependencies: { a: '1.0.0' },
    }));
    const packages: Record<string, Record<string, unknown>> = { '': {} };
    let path = 'node_modules/a';
    for (let i = 0; i < 7; i++) {
      packages[path] = {};
      path += `/node_modules/dep-${i}`;
    }
    await writeFile(join(tempDir, 'package-lock.json'), JSON.stringify({ packages }));

    const result = await auditDirectory(tempDir, { checkCves: false });
    expect(result.findings.some(f => f.id === 'deep_dep_tree')).toBe(true);
  });

  it('flags install scripts', async () => {
    await writeFile(join(tempDir, 'package.json'), JSON.stringify({
      dependencies: { a: '1.0.0' },
      scripts: { postinstall: 'node inject.js' },
    }));
    await writeFile(join(tempDir, 'package-lock.json'), JSON.stringify({ packages: { '': {} } }));

    const result = await auditDirectory(tempDir, { checkCves: false });
    expect(result.findings.some(f => f.id === 'install_script')).toBe(true);
  });

  it('parses requirements.txt', async () => {
    await writeFile(join(tempDir, 'requirements.txt'), 'requests==2.31.0\nflask>=3.0.0\n');

    const result = await auditDirectory(tempDir, { checkCves: false });
    expect(result.manifests_found).toContain('requirements.txt');
    expect(result.dependencies_count).toBe(2);
    expect(result.findings.some(f => f.dependency === 'flask')).toBe(true);
  });

  it('detects PEP 723 inline deps', async () => {
    await writeFile(join(tempDir, 'main.py'), `# script dependencies\n# httpx\n# bs4\n`);

    const result = await auditDirectory(tempDir, { checkCves: false });
    expect(result.findings.some(f => f.category === 'pep723')).toBe(true);
  });

  it('rejects critical PEP 723 unpinned dep', async () => {
    await writeFile(join(tempDir, 'main.py'), `# script dependencies\n# requests\n`);

    const result = await auditDirectory(tempDir, { checkCves: false });
    expect(result.status).toBe('reject');
    expect(result.summary.critical).toBeGreaterThan(0);
  });

  it('returns pass for empty directory', async () => {
    const result = await auditDirectory(tempDir, { checkCves: false });
    expect(result.status).toBe('pass');
    expect(result.dependencies_count).toBe(0);
  });

  it('returns pass for nonexistent directory', async () => {
    const result = await auditDirectory(join(tempDir, 'nonexistent'), { checkCves: false });
    expect(result.status).toBe('pass');
  });

  it('flags suspicious git deps', async () => {
    await writeFile(join(tempDir, 'package.json'), JSON.stringify({
      dependencies: { evil: 'git+https://github.com/evil/pkg.git' },
    }));
    await writeFile(join(tempDir, 'package-lock.json'), JSON.stringify({ packages: { '': {} } }));

    const result = await auditDirectory(tempDir, { checkCves: false });
    expect(result.findings.some(f => f.id === 'git_dependency')).toBe(true);
  });

  it('has duration_ms populated', async () => {
    await writeFile(join(tempDir, 'SKILL.md'), '# Test\n');
    const result = await auditDirectory(tempDir, { checkCves: false });
    expect(result.duration_ms).toBeGreaterThanOrEqual(0);
  });

  it('sorts findings by severity (critical first)', async () => {
    await writeFile(join(tempDir, 'package.json'), JSON.stringify({
      dependencies: { a: '^1.0.0' },
      scripts: { preinstall: 'node evil.js' },
    }));
    await writeFile(join(tempDir, 'main.py'), `# script dependencies\n# requests\n`);

    const result = await auditDirectory(tempDir, { checkCves: false });
    if (result.findings.length >= 2) {
      for (let i = 1; i < result.findings.length; i++) {
        const prevOrder = { critical: 0, high: 1, medium: 2, low: 3 }[result.findings[i - 1].severity];
        const currOrder = { critical: 0, high: 1, medium: 2, low: 3 }[result.findings[i].severity];
        expect(prevOrder).toBeLessThanOrEqual(currOrder);
      }
    }
  });
});
