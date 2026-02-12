import { describe, it, expect } from 'vitest';
import { buildNodePermissionArgs, getNodeSystemPaths } from '../node-permissions.js';
import type { PermissionsPolicy } from '../types.js';

describe('buildNodePermissionArgs', () => {
  const basePolicy: PermissionsPolicy = {
    filesystem: { read: ['/skill'], write: [] },
    network: { type: 'none' },
    exec: false,
    agentCapabilities: {
      memoryRead: false,
      memoryWrite: false,
      spawnAgents: false,
      modifySystemPrompt: false,
    },
  };

  it('adds --experimental-permission flag', () => {
    const result = buildNodePermissionArgs(basePolicy, 'node', ['index.js'], {});
    expect(result.env.NODE_OPTIONS).toContain('--experimental-permission');
  });

  it('includes declared read paths and system paths in --allow-fs-read', () => {
    const result = buildNodePermissionArgs(basePolicy, 'node', ['index.js'], {});
    expect(result.env.NODE_OPTIONS).toContain('--allow-fs-read=');
    expect(result.env.NODE_OPTIONS).toContain('/skill');
    const sysPaths = getNodeSystemPaths();
    for (const sp of sysPaths) {
      expect(result.env.NODE_OPTIONS).toContain(sp);
    }
  });

  it('adds --allow-fs-write for write paths', () => {
    const policy: PermissionsPolicy = {
      ...basePolicy,
      filesystem: { read: ['/skill'], write: ['/tmp/out'] },
    };
    const result = buildNodePermissionArgs(policy, 'node', ['index.js'], {});
    expect(result.env.NODE_OPTIONS).toContain('--allow-fs-write=/tmp/out');
  });

  it('does not add --allow-fs-write when write paths empty', () => {
    const result = buildNodePermissionArgs(basePolicy, 'node', ['index.js'], {});
    expect(result.env.NODE_OPTIONS).not.toContain('--allow-fs-write');
  });

  it('adds --allow-child-process when exec is true', () => {
    const policy: PermissionsPolicy = { ...basePolicy, exec: true };
    const result = buildNodePermissionArgs(policy, 'node', ['index.js'], {});
    expect(result.env.NODE_OPTIONS).toContain('--allow-child-process');
  });

  it('does not add --allow-child-process when exec is false', () => {
    const result = buildNodePermissionArgs(basePolicy, 'node', ['index.js'], {});
    expect(result.env.NODE_OPTIONS).not.toContain('--allow-child-process');
  });

  it('preserves command and args', () => {
    const result = buildNodePermissionArgs(basePolicy, 'node', ['--harmony', 'app.js'], {});
    expect(result.command).toBe('node');
    expect(result.args).toEqual(['--harmony', 'app.js']);
  });

  it('reports backend as node-permissions', () => {
    const result = buildNodePermissionArgs(basePolicy, 'node', [], {});
    expect(result.backend).toBe('node-permissions');
  });

  it('reports filesystem and exec as enforced, network as not', () => {
    const result = buildNodePermissionArgs(basePolicy, 'node', [], {});
    expect(result.enforced.filesystem).toBe(true);
    expect(result.enforced.network).toBe(false);
    expect(result.enforced.exec).toBe(true);
  });
});
