export type SandboxStatus = 'pass' | 'flag' | 'reject';

export interface SandboxConfig {
  timeout?: number;
  maxMemory?: number;
  allowNetwork?: boolean;
  allowedReadPaths?: string[];
  allowedWritePaths?: string[];
  entrypoint?: string;
  entrypointArgs?: string[];
  env?: Record<string, string>;
  cwd?: string;
}

export interface SandboxViolation {
  type: 'filesystem_read' | 'filesystem_write' | 'network' | 'exec' | 'timeout' | 'memory' | 'crash';
  severity: 'critical' | 'high' | 'medium';
  message: string;
  detail?: string;
}

export interface ProcessOutput {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  signal: string | null;
  timedOut: boolean;
}

export interface SandboxResult {
  status: SandboxStatus;
  duration_ms: number;
  process: ProcessOutput;
  violations: SandboxViolation[];
  summary: {
    critical: number;
    high: number;
    medium: number;
  };
}

export interface PermissionsJson {
  declared?: {
    filesystem?: {
      read?: string[];
      write?: string[];
    };
    network?: boolean | string[];
    exec?: boolean;
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
  network?: boolean | string[];
  exec?: boolean;
  agent_capabilities?: {
    memory_read?: boolean;
    memory_write?: boolean;
    spawn_agents?: boolean;
    modify_system_prompt?: boolean;
  };
}

export const DEFAULT_TIMEOUT = 30_000;
export const DEFAULT_MAX_MEMORY = 256;
