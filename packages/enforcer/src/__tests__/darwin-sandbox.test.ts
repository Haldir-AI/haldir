import { describe, it, expect } from 'vitest';
import { generateSandboxProfile } from '../darwin-sandbox.js';
import type { PermissionsPolicy } from '../types.js';

describe('generateSandboxProfile', () => {
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

  it('starts with version 1 and deny default', () => {
    const profile = generateSandboxProfile(basePolicy);
    expect(profile).toContain('(version 1)');
    expect(profile).toContain('(deny default)');
  });

  it('allows read from declared paths', () => {
    const profile = generateSandboxProfile(basePolicy);
    expect(profile).toContain('(allow file-read* (subpath "/skill"))');
  });

  it('allows read from system directories', () => {
    const profile = generateSandboxProfile(basePolicy);
    expect(profile).toContain('(allow file-read* (subpath "/usr/lib"))');
    expect(profile).toContain('(allow file-read* (subpath "/System"))');
  });

  it('allows write to declared paths', () => {
    const policy: PermissionsPolicy = {
      ...basePolicy,
      filesystem: { read: ['/skill'], write: ['/tmp/output'] },
    };
    const profile = generateSandboxProfile(policy);
    expect(profile).toContain('(allow file-write* (subpath "/tmp/output"))');
  });

  it('denies network when policy is none', () => {
    const profile = generateSandboxProfile(basePolicy);
    expect(profile).toContain('Network denied');
    expect(profile).not.toContain('(allow network*)');
  });

  it('allows all network when policy is all', () => {
    const policy: PermissionsPolicy = {
      ...basePolicy,
      network: { type: 'all' },
    };
    const profile = generateSandboxProfile(policy);
    expect(profile).toContain('(allow network*)');
  });

  it('allows outbound tcp for allowlist with per-domain filtering', () => {
    const policy: PermissionsPolicy = {
      ...basePolicy,
      network: { type: 'allowlist', domains: ['api.example.com'] },
    };
    const profile = generateSandboxProfile(policy);
    expect(profile).toContain('(allow network-outbound (remote tcp "api.example.com"))');
    expect(profile).toContain('(allow system-socket)');
  });

  it('denies network for empty allowlist', () => {
    const policy: PermissionsPolicy = {
      ...basePolicy,
      network: { type: 'allowlist', domains: [] },
    };
    const profile = generateSandboxProfile(policy);
    expect(profile).toContain('Allowlist with no domains');
    expect(profile).not.toContain('network-outbound');
  });

  it('denies process-exec when exec is false', () => {
    const profile = generateSandboxProfile(basePolicy);
    expect(profile).not.toContain('(allow process-exec*)');
    expect(profile).not.toContain('(allow process-fork)');
  });

  it('allows process-exec when exec is true', () => {
    const policy: PermissionsPolicy = { ...basePolicy, exec: true };
    const profile = generateSandboxProfile(policy);
    expect(profile).toContain('(allow process-exec*)');
    expect(profile).toContain('(allow process-fork)');
  });

  it('includes multiple read paths', () => {
    const policy: PermissionsPolicy = {
      ...basePolicy,
      filesystem: { read: ['/skill', '/data', '/config'], write: [] },
    };
    const profile = generateSandboxProfile(policy);
    expect(profile).toContain('(subpath "/skill")');
    expect(profile).toContain('(subpath "/data")');
    expect(profile).toContain('(subpath "/config")');
  });

  it('escapes double quotes in paths', () => {
    const policy: PermissionsPolicy = {
      ...basePolicy,
      filesystem: { read: ['/path/with "quotes'], write: [] },
    };
    const profile = generateSandboxProfile(policy);
    expect(profile).toContain('/path/with \\"quotes');
  });

  it('allows tmp directory writes', () => {
    const profile = generateSandboxProfile(basePolicy);
    expect(profile).toContain('file-write*');
  });
});
