import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, mkdir, rm, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { enforceAndRun, loadPermissions, detectBackend } from '../runner.js';
import { compilePolicy } from '../compiler.js';

describe('loadPermissions', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await realpath(await mkdtemp(join(tmpdir(), 'haldir-enforcer-')));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('returns null when .vault/ missing', async () => {
    expect(await loadPermissions(tempDir)).toBeNull();
  });

  it('returns null when permissions.json missing', async () => {
    await mkdir(join(tempDir, '.vault'));
    expect(await loadPermissions(tempDir)).toBeNull();
  });

  it('loads valid permissions.json', async () => {
    await mkdir(join(tempDir, '.vault'));
    await writeFile(join(tempDir, '.vault', 'permissions.json'), JSON.stringify({
      schema_version: '1.0',
      declared: {
        filesystem: { read: ['./data'] },
        network: 'none',
      },
    }));

    const perms = await loadPermissions(tempDir);
    expect(perms).not.toBeNull();
    expect(perms!.declared?.filesystem?.read).toEqual(['./data']);
  });
});

describe('detectBackend', () => {
  it('returns explicit backend when specified', () => {
    expect(detectBackend('node-permissions')).toBe('node-permissions');
    expect(detectBackend('darwin-sandbox')).toBe('darwin-sandbox');
    expect(detectBackend('linux-landlock')).toBe('linux-landlock');
  });

  it('returns platform-appropriate backend for auto', () => {
    const backend = detectBackend('auto');
    expect(['node-permissions', 'darwin-sandbox', 'linux-landlock']).toContain(backend);
  });

  it('returns platform-appropriate backend for undefined', () => {
    const backend = detectBackend();
    expect(['node-permissions', 'darwin-sandbox', 'linux-landlock']).toContain(backend);
  });
});

describe('enforceAndRun', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await realpath(await mkdtemp(join(tmpdir(), 'haldir-enforce-')));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('runs a clean script successfully', async () => {
    await writeFile(join(tempDir, 'hello.js'), 'console.log("hello");');

    const policy = compilePolicy({
      filesystem: { read: [tempDir] },
      network: false,
    }, tempDir);

    const result = await enforceAndRun(
      tempDir,
      process.execPath,
      [join(tempDir, 'hello.js')],
      policy,
      { backend: 'node-permissions', timeout: 10000 },
    );

    expect(result.stdout.trim()).toBe('hello');
    expect(result.violations).toHaveLength(0);
    expect(result.backend).toBe('node-permissions');
    expect(result.enforced.filesystem).toBe(true);
    expect(result.duration_ms).toBeGreaterThanOrEqual(0);
  }, 15000);

  it('detects filesystem read violation', async () => {
    await writeFile(join(tempDir, 'bad-read.js'), `
      const fs = require('fs');
      fs.readFileSync('/etc/passwd');
    `);

    const policy = compilePolicy({
      filesystem: { read: [tempDir] },
    }, tempDir);

    const result = await enforceAndRun(
      tempDir,
      process.execPath,
      [join(tempDir, 'bad-read.js')],
      policy,
      { backend: 'node-permissions', timeout: 10000 },
    );

    expect(result.violations.length).toBeGreaterThan(0);
  }, 15000);

  it('enforces timeout', async () => {
    await writeFile(join(tempDir, 'hang.js'), 'setTimeout(() => {}, 60000);');

    const policy = compilePolicy({ filesystem: { read: [tempDir] } }, tempDir);

    const result = await enforceAndRun(
      tempDir,
      process.execPath,
      [join(tempDir, 'hang.js')],
      policy,
      { backend: 'node-permissions', timeout: 1000 },
    );

    expect(result.violations.some(v => v.type === 'timeout')).toBe(true);
    expect(result.status).toBe('violation');
  }, 10000);

  it('calls onViolation callback', async () => {
    await writeFile(join(tempDir, 'hang2.js'), 'setTimeout(() => {}, 60000);');

    const policy = compilePolicy({ filesystem: { read: [tempDir] } }, tempDir);
    const violations: Array<{ type: string }> = [];

    await enforceAndRun(
      tempDir,
      process.execPath,
      [join(tempDir, 'hang2.js')],
      policy,
      {
        backend: 'node-permissions',
        timeout: 500,
        onViolation: (v) => violations.push(v),
      },
    );

    expect(violations.length).toBeGreaterThan(0);
  }, 10000);

  it('returns non-clean status for non-zero exit', async () => {
    await writeFile(join(tempDir, 'fail.js'), 'process.exit(1);');

    const policy = compilePolicy({ filesystem: { read: [tempDir] } }, tempDir);

    const result = await enforceAndRun(
      tempDir,
      process.execPath,
      [join(tempDir, 'fail.js')],
      policy,
      { backend: 'node-permissions', timeout: 5000 },
    );

    expect(result.exitCode).not.toBe(0);
    expect(result.status).not.toBe('clean');
  }, 10000);

  it('reports enforced capabilities', async () => {
    await writeFile(join(tempDir, 'ok.js'), 'console.log("ok");');
    const policy = compilePolicy({}, tempDir);

    const result = await enforceAndRun(
      tempDir,
      process.execPath,
      [join(tempDir, 'ok.js')],
      policy,
      { backend: 'node-permissions', timeout: 5000 },
    );

    expect(result.enforced).toEqual({
      filesystem: true,
      network: false,
      exec: true,
    });
  }, 10000);
});
