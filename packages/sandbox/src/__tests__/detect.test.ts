import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { detectEntrypoint } from '../detect.js';

describe('detectEntrypoint', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'haldir-detect-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('detects package.json with main', async () => {
    await writeFile(join(tempDir, 'package.json'), JSON.stringify({ main: 'server.js' }));
    const ep = await detectEntrypoint(tempDir);
    expect(ep.runtime).toBe('node');
    expect(ep.command).toBe('node');
    expect(ep.args).toEqual(['server.js']);
  });

  it('detects package.json with start script', async () => {
    await writeFile(join(tempDir, 'package.json'), JSON.stringify({
      scripts: { start: 'node app.js' },
    }));
    const ep = await detectEntrypoint(tempDir);
    expect(ep.command).toBe('npm');
    expect(ep.args).toEqual(['start']);
  });

  it('prefers start script over main', async () => {
    await writeFile(join(tempDir, 'package.json'), JSON.stringify({
      main: 'lib.js',
      scripts: { start: 'node app.js' },
    }));
    const ep = await detectEntrypoint(tempDir);
    expect(ep.command).toBe('npm');
  });

  it('detects main.py', async () => {
    await writeFile(join(tempDir, 'main.py'), 'print("hello")\n');
    const ep = await detectEntrypoint(tempDir);
    expect(ep.runtime).toBe('python');
    expect(ep.command).toBe('python3');
    expect(ep.args).toEqual(['main.py']);
  });

  it('detects app.py', async () => {
    await writeFile(join(tempDir, 'app.py'), 'print("hello")\n');
    const ep = await detectEntrypoint(tempDir);
    expect(ep.runtime).toBe('python');
    expect(ep.args).toEqual(['app.py']);
  });

  it('detects index.js', async () => {
    await writeFile(join(tempDir, 'index.js'), 'console.log("hi")\n');
    const ep = await detectEntrypoint(tempDir);
    expect(ep.runtime).toBe('node');
    expect(ep.args).toEqual(['index.js']);
  });

  it('detects index.mjs', async () => {
    await writeFile(join(tempDir, 'index.mjs'), 'console.log("hi")\n');
    const ep = await detectEntrypoint(tempDir);
    expect(ep.runtime).toBe('node');
    expect(ep.args).toEqual(['index.mjs']);
  });

  it('detects run.sh', async () => {
    await writeFile(join(tempDir, 'run.sh'), 'echo hello\n');
    const ep = await detectEntrypoint(tempDir);
    expect(ep.runtime).toBe('shell');
    expect(ep.command).toBe('sh');
  });

  it('returns unknown for empty dir', async () => {
    const ep = await detectEntrypoint(tempDir);
    expect(ep.runtime).toBe('unknown');
  });

  it('returns unknown for nonexistent dir', async () => {
    const ep = await detectEntrypoint(join(tempDir, 'nonexistent'));
    expect(ep.runtime).toBe('unknown');
  });
});
