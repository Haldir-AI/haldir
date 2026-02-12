import { describe, it, expect } from 'vitest';
import { compilePolicy } from '../compiler.js';

describe('compilePolicy', () => {
  const skillDir = '/skills/my-skill';

  it('returns deny-all policy for null permissions', () => {
    const policy = compilePolicy(null, skillDir);
    expect(policy.filesystem.read).toEqual([skillDir]);
    expect(policy.filesystem.write).toEqual([]);
    expect(policy.network).toEqual({ type: 'none' });
    expect(policy.exec).toBe(false);
    expect(policy.agentCapabilities.memoryRead).toBe(false);
    expect(policy.agentCapabilities.spawnAgents).toBe(false);
  });

  it('resolves relative filesystem paths against skillDir', () => {
    const policy = compilePolicy({
      filesystem: { read: ['./data'], write: ['./output'] },
    }, skillDir);

    expect(policy.filesystem.read).toContain(skillDir);
    expect(policy.filesystem.read.some(p => p.endsWith('/data'))).toBe(true);
    expect(policy.filesystem.write.some(p => p.endsWith('/output'))).toBe(true);
  });

  it('preserves absolute filesystem paths', () => {
    const policy = compilePolicy({
      filesystem: { read: ['/tmp/shared'], write: ['/tmp/out'] },
    }, skillDir);

    expect(policy.filesystem.read).toContain('/tmp/shared');
    expect(policy.filesystem.write).toContain('/tmp/out');
  });

  it('resolves network: "none" to none', () => {
    const policy = compilePolicy({ network: 'none' }, skillDir);
    expect(policy.network).toEqual({ type: 'none' });
  });

  it('resolves network: false to none', () => {
    const policy = compilePolicy({ network: false }, skillDir);
    expect(policy.network).toEqual({ type: 'none' });
  });

  it('resolves network: true to all', () => {
    const policy = compilePolicy({ network: true }, skillDir);
    expect(policy.network).toEqual({ type: 'all' });
  });

  it('resolves network array to allowlist', () => {
    const policy = compilePolicy({ network: ['api.example.com', 'cdn.example.com'] }, skillDir);
    expect(policy.network).toEqual({
      type: 'allowlist',
      domains: ['api.example.com', 'cdn.example.com'],
    });
  });

  it('resolves empty network array to none', () => {
    const policy = compilePolicy({ network: [] }, skillDir);
    expect(policy.network).toEqual({ type: 'none' });
  });

  it('resolves exec: false to false', () => {
    const policy = compilePolicy({ exec: false }, skillDir);
    expect(policy.exec).toBe(false);
  });

  it('resolves exec: true to true', () => {
    const policy = compilePolicy({ exec: true }, skillDir);
    expect(policy.exec).toBe(true);
  });

  it('resolves exec array with items to true', () => {
    const policy = compilePolicy({ exec: ['node', 'python'] }, skillDir);
    expect(policy.exec).toBe(true);
  });

  it('resolves agent_capabilities', () => {
    const policy = compilePolicy({
      agent_capabilities: {
        memory_read: true,
        memory_write: true,
        spawn_agents: false,
        modify_system_prompt: false,
      },
    }, skillDir);

    expect(policy.agentCapabilities.memoryRead).toBe(true);
    expect(policy.agentCapabilities.memoryWrite).toBe(true);
    expect(policy.agentCapabilities.spawnAgents).toBe(false);
    expect(policy.agentCapabilities.modifySystemPrompt).toBe(false);
  });

  it('handles declared wrapper format', () => {
    const policy = compilePolicy({
      schema_version: '1.0',
      declared: {
        filesystem: { read: ['./data'] },
        network: 'none',
        exec: [],
        agent_capabilities: { memory_read: true },
      },
    }, skillDir);

    expect(policy.filesystem.read.some(p => p.endsWith('/data'))).toBe(true);
    expect(policy.network).toEqual({ type: 'none' });
    expect(policy.exec).toBe(false);
    expect(policy.agentCapabilities.memoryRead).toBe(true);
  });

  it('defaults missing fields to deny', () => {
    const policy = compilePolicy({}, skillDir);
    expect(policy.filesystem.read).toEqual([skillDir]);
    expect(policy.filesystem.write).toEqual([]);
    expect(policy.network).toEqual({ type: 'none' });
    expect(policy.exec).toBe(false);
  });
});
