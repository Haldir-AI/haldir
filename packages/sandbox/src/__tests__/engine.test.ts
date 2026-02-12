import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { sandboxSkill } from '../engine.js';

describe('sandboxSkill', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'haldir-sandbox-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('passes for clean node script', async () => {
    await writeFile(join(tempDir, 'index.js'), 'console.log("clean output");\n');
    const result = await sandboxSkill(tempDir, { timeout: 5000 });
    expect(result.status).toBe('pass');
    expect(result.process.stdout).toContain('clean output');
    expect(result.duration_ms).toBeGreaterThanOrEqual(0);
  });

  it('detects network activity in undeclared skill', async () => {
    await writeFile(join(tempDir, 'index.js'),
      'console.log("fetch(\\"https://evil.com\\")");\n');
    const result = await sandboxSkill(tempDir, { timeout: 5000 });
    expect(result.violations.some(v => v.type === 'network')).toBe(true);
  });

  it('passes network check when permissions declare network', async () => {
    await mkdir(join(tempDir, '.vault'));
    await writeFile(join(tempDir, '.vault', 'permissions.json'), JSON.stringify({
      network: true,
    }));
    await writeFile(join(tempDir, 'index.js'),
      'console.log("fetch(\\"https://api.example.com\\")");\n');
    const result = await sandboxSkill(tempDir, { timeout: 5000 });
    expect(result.violations.some(v => v.type === 'network')).toBe(false);
  });

  it('flags timeout', async () => {
    await writeFile(join(tempDir, 'index.js'),
      'setTimeout(() => {}, 60000);\n');
    const result = await sandboxSkill(tempDir, { timeout: 500 });
    expect(result.violations.some(v => v.type === 'timeout')).toBe(true);
    expect(result.status).toBe('flag');
  }, 10000);

  it('handles missing entrypoint gracefully', async () => {
    const result = await sandboxSkill(tempDir, { timeout: 2000 });
    expect(result.process.exitCode).toBe(0);
  });

  it('custom entrypoint override', async () => {
    await writeFile(join(tempDir, 'custom.js'), 'console.log("custom");\n');
    const result = await sandboxSkill(tempDir, {
      timeout: 5000,
      entrypoint: 'node custom.js',
    });
    expect(result.process.stdout).toContain('custom');
  });

  it('detects exec pattern in output', async () => {
    await writeFile(join(tempDir, 'index.js'),
      'console.log("spawning subprocess: spawn(\\"/bin/sh\\")");\n');
    const result = await sandboxSkill(tempDir, { timeout: 5000 });
    expect(result.violations.some(v => v.type === 'exec')).toBe(true);
  });

  it('passes exec check when declared', async () => {
    await mkdir(join(tempDir, '.vault'));
    await writeFile(join(tempDir, '.vault', 'permissions.json'), JSON.stringify({
      exec: true,
    }));
    await writeFile(join(tempDir, 'index.js'),
      'console.log("spawning: spawn(\\"/bin/sh\\")");\n');
    const result = await sandboxSkill(tempDir, { timeout: 5000 });
    expect(result.violations.some(v => v.type === 'exec')).toBe(false);
  });

  it('has duration populated', async () => {
    await writeFile(join(tempDir, 'index.js'), 'console.log("ok");\n');
    const result = await sandboxSkill(tempDir, { timeout: 5000 });
    expect(result.duration_ms).toBeGreaterThanOrEqual(0);
  });

  it('computes summary correctly', async () => {
    await writeFile(join(tempDir, 'index.js'),
      'const {exec} = require("child_process"); console.log("fetch(\\"http://evil.com\\")");\n');
    const result = await sandboxSkill(tempDir, { timeout: 5000 });
    expect(result.summary.critical + result.summary.high + result.summary.medium).toBe(result.violations.length);
  });
});
