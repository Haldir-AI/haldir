import { resolve } from 'node:path';
import type { PermissionsJson, PermissionsPolicy, NetworkPolicy } from './types.js';

export function compilePolicy(
  perms: PermissionsJson | null,
  skillDir: string,
): PermissionsPolicy {
  if (!perms) return denyAll(skillDir);

  const decl = perms.declared ?? perms;

  return {
    filesystem: resolveFilesystem(decl, skillDir),
    network: resolveNetwork(decl),
    exec: resolveExec(decl),
    agentCapabilities: resolveAgentCapabilities(decl),
  };
}

function denyAll(skillDir: string): PermissionsPolicy {
  return {
    filesystem: { read: [resolve(skillDir)], write: [] },
    network: { type: 'none' },
    exec: false,
    agentCapabilities: {
      memoryRead: false,
      memoryWrite: false,
      spawnAgents: false,
      modifySystemPrompt: false,
    },
  };
}

interface DeclBlock {
  filesystem?: { read?: string[]; write?: string[] };
  network?: boolean | string | string[];
  exec?: boolean | string[];
  agent_capabilities?: {
    memory_read?: boolean;
    memory_write?: boolean;
    spawn_agents?: boolean;
    modify_system_prompt?: boolean;
  };
}

function resolveFilesystem(decl: DeclBlock, skillDir: string): PermissionsPolicy['filesystem'] {
  const readPaths = decl.filesystem?.read ?? [];
  const writePaths = decl.filesystem?.write ?? [];

  return {
    read: [
      resolve(skillDir),
      ...readPaths.map(p => p.startsWith('/') ? p : resolve(skillDir, p)),
    ],
    write: writePaths.map(p => p.startsWith('/') ? p : resolve(skillDir, p)),
  };
}

function resolveNetwork(decl: DeclBlock): NetworkPolicy {
  const net = decl.network;
  if (net === undefined || net === false || net === 'none') {
    return { type: 'none' };
  }
  if (net === true) {
    return { type: 'all' };
  }
  if (typeof net === 'string') {
    return { type: 'allowlist', domains: [net] };
  }
  if (Array.isArray(net)) {
    return net.length === 0
      ? { type: 'none' }
      : { type: 'allowlist', domains: net };
  }
  return { type: 'none' };
}

function resolveExec(decl: DeclBlock): boolean {
  const exec = decl.exec;
  if (exec === undefined || exec === false) return false;
  if (exec === true) return true;
  if (Array.isArray(exec)) return exec.length > 0;
  return false;
}

function resolveAgentCapabilities(decl: DeclBlock): PermissionsPolicy['agentCapabilities'] {
  const cap = decl.agent_capabilities;
  return {
    memoryRead: cap?.memory_read ?? false,
    memoryWrite: cap?.memory_write ?? false,
    spawnAgents: cap?.spawn_agents ?? false,
    modifySystemPrompt: cap?.modify_system_prompt ?? false,
  };
}
