export type EnforcementBackend = 'node-permissions' | 'darwin-sandbox' | 'linux-landlock';

export interface PermissionsPolicy {
  filesystem: {
    read: string[];
    write: string[];
  };
  network: NetworkPolicy;
  exec: boolean;
  agentCapabilities: {
    memoryRead: boolean;
    memoryWrite: boolean;
    spawnAgents: boolean;
    modifySystemPrompt: boolean;
  };
}

export type NetworkPolicy =
  | { type: 'none' }
  | { type: 'all' }
  | { type: 'allowlist'; domains: string[] };

export interface EnforcementConfig {
  backend?: EnforcementBackend | 'auto';
  timeout?: number;
  maxMemory?: number;
  env?: Record<string, string>;
  cwd?: string;
  onViolation?: (violation: EnforcementViolation) => void;
}

export interface EnforcementViolation {
  type: 'filesystem_read' | 'filesystem_write' | 'network' | 'exec' | 'timeout' | 'memory' | 'crash';
  severity: 'critical' | 'high' | 'medium';
  message: string;
  detail?: string;
  timestamp: number;
}

export interface EnforcementResult {
  status: 'clean' | 'violation' | 'error';
  exitCode: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  violations: EnforcementViolation[];
  backend: EnforcementBackend;
  duration_ms: number;
  enforced: {
    filesystem: boolean;
    network: boolean;
    exec: boolean;
  };
}

export interface SpawnPolicy {
  command: string;
  args: string[];
  env: Record<string, string>;
  backend: EnforcementBackend;
  enforced: {
    filesystem: boolean;
    network: boolean;
    exec: boolean;
  };
}

export interface PermissionsJson {
  schema_version?: string;
  declared?: {
    filesystem?: {
      read?: string[];
      write?: string[];
    };
    network?: string | string[];
    exec?: string[];
    agent_capabilities?: {
      memory_read?: boolean;
      memory_write?: boolean;
      spawn_agents?: boolean;
      modify_system_prompt?: boolean;
    };
  };
  filesystem?: {
    read?: string[];
    write?: string[];
  };
  network?: boolean | string | string[];
  exec?: boolean | string[];
  agent_capabilities?: {
    memory_read?: boolean;
    memory_write?: boolean;
    spawn_agents?: boolean;
    modify_system_prompt?: boolean;
  };
}

export const DEFAULT_TIMEOUT = 30_000;
export const DEFAULT_MAX_MEMORY = 256;
