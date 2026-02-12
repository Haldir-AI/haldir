import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadPermissions, permissionsToSandboxConfig } from '../permissions.js';

describe('loadPermissions', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'haldir-perm-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('loads valid permissions.json', async () => {
    await mkdir(join(tempDir, '.vault'));
    await writeFile(join(tempDir, '.vault', 'permissions.json'), JSON.stringify({
      filesystem: { read: ['./data'], write: ['./output'] },
      network: true,
      exec: false,
    }));

    const perms = await loadPermissions(tempDir);
    expect(perms).not.toBeNull();
    expect(perms?.network).toBe(true);
    expect(perms?.filesystem?.read).toEqual(['./data']);
  });

  it('returns null when no .vault dir', async () => {
    const perms = await loadPermissions(tempDir);
    expect(perms).toBeNull();
  });

  it('returns null for invalid JSON', async () => {
    await mkdir(join(tempDir, '.vault'));
    await writeFile(join(tempDir, '.vault', 'permissions.json'), 'not json');
    const perms = await loadPermissions(tempDir);
    expect(perms).toBeNull();
  });
});

describe('permissionsToSandboxConfig', () => {
  it('defaults to read-only skill dir when no permissions', () => {
    const config = permissionsToSandboxConfig(null, '/skill');
    expect(config.allowNetwork).toBe(false);
    expect(config.allowedReadPaths).toEqual(['/skill']);
    expect(config.allowedWritePaths).toEqual([]);
  });

  it('resolves relative paths against skill dir', () => {
    const config = permissionsToSandboxConfig({
      filesystem: { read: ['./data'], write: ['./output'] },
    }, '/skill');
    expect(config.allowedReadPaths).toEqual(['/skill/data']);
    expect(config.allowedWritePaths).toEqual(['/skill/output']);
  });

  it('preserves absolute paths', () => {
    const config = permissionsToSandboxConfig({
      filesystem: { read: ['/tmp/shared'] },
    }, '/skill');
    expect(config.allowedReadPaths).toEqual(['/tmp/shared']);
  });

  it('enables network when declared true', () => {
    const config = permissionsToSandboxConfig({ network: true }, '/skill');
    expect(config.allowNetwork).toBe(true);
  });

  it('enables network when declared as array', () => {
    const config = permissionsToSandboxConfig({
      network: ['api.example.com'],
    }, '/skill');
    expect(config.allowNetwork).toBe(true);
  });

  it('disables network when false', () => {
    const config = permissionsToSandboxConfig({ network: false }, '/skill');
    expect(config.allowNetwork).toBe(false);
  });

  it('defaults read to skill dir when filesystem omitted', () => {
    const config = permissionsToSandboxConfig({}, '/skill');
    expect(config.allowedReadPaths).toEqual(['/skill']);
  });
});
