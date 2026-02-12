import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { collectSkillContent } from '../collect.js';

describe('collectSkillContent', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'haldir-collect-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('collects from package.json', async () => {
    await writeFile(join(tempDir, 'package.json'), JSON.stringify({
      name: 'my-skill',
      version: '2.0.0',
      description: 'A cool skill',
    }));
    await writeFile(join(tempDir, 'index.js'), 'console.log("hi");\n');

    const content = await collectSkillContent(tempDir);
    expect(content.name).toBe('my-skill');
    expect(content.version).toBe('2.0.0');
    expect(content.description).toBe('A cool skill');
    expect(content.files.length).toBeGreaterThanOrEqual(1);
  });

  it('collects from SKILL.md when no package.json', async () => {
    await writeFile(join(tempDir, 'SKILL.md'), '# Weather Lookup\nGets weather data.\n');

    const content = await collectSkillContent(tempDir);
    expect(content.name).toBe('Weather Lookup');
    expect(content.description).toContain('Weather Lookup');
  });

  it('includes permissions from .vault', async () => {
    await mkdir(join(tempDir, '.vault'));
    await writeFile(join(tempDir, '.vault', 'permissions.json'), JSON.stringify({
      network: true,
    }));
    await writeFile(join(tempDir, 'index.js'), 'fetch("https://api.com");\n');

    const content = await collectSkillContent(tempDir);
    expect(content.permissions).toMatchObject({ network: true });
  });

  it('collects code files', async () => {
    await writeFile(join(tempDir, 'main.py'), 'print("hello")\n');
    await writeFile(join(tempDir, 'config.yaml'), 'key: value\n');
    await writeFile(join(tempDir, 'readme.txt'), 'not collected\n');

    const content = await collectSkillContent(tempDir);
    const paths = content.files.map(f => f.path);
    expect(paths).toContain('main.py');
    expect(paths).toContain('config.yaml');
    expect(paths).not.toContain('readme.txt');
  });

  it('skips .vault and node_modules', async () => {
    await mkdir(join(tempDir, '.vault'));
    await writeFile(join(tempDir, '.vault', 'signature.json'), '{}');
    await mkdir(join(tempDir, 'node_modules'));
    await writeFile(join(tempDir, 'node_modules', 'pkg.js'), '');
    await writeFile(join(tempDir, 'index.js'), 'main();\n');

    const content = await collectSkillContent(tempDir);
    const paths = content.files.map(f => f.path);
    expect(paths).not.toContain('.vault/signature.json');
    expect(paths).not.toContain('node_modules/pkg.js');
    expect(paths).toContain('index.js');
  });

  it('handles empty directory', async () => {
    const content = await collectSkillContent(tempDir);
    expect(content.name).toBe('unknown');
    expect(content.files).toHaveLength(0);
  });

  it('handles nonexistent directory', async () => {
    const content = await collectSkillContent(join(tempDir, 'nope'));
    expect(content.files).toHaveLength(0);
  });
});
