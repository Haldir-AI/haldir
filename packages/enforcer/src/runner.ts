import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { platform } from 'node:os';
import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { compilePolicy } from './compiler.js';
import { buildNodePermissionArgs } from './node-permissions.js';
import { buildDarwinSandboxArgs, cleanupProfile } from './darwin-sandbox.js';
import { buildLinuxLandlockArgs } from './linux-landlock.js';
import type {
  PermissionsJson,
  PermissionsPolicy,
  EnforcementConfig,
  EnforcementResult,
  EnforcementViolation,
  EnforcementBackend,
  SpawnPolicy,
} from './types.js';
import { DEFAULT_TIMEOUT, DEFAULT_MAX_MEMORY } from './types.js';

export async function loadPermissions(skillDir: string): Promise<PermissionsJson | null> {
  try {
    const raw = await readFile(join(skillDir, '.vault', 'permissions.json'), 'utf-8');
    const parsed = JSON.parse(raw) as PermissionsJson;

    const attRaw = await readFile(join(skillDir, '.vault', 'attestation.json'), 'utf-8');
    const attestation = JSON.parse(attRaw) as { permissions_hash?: string };
    if (!attestation.permissions_hash) return null;

    const actual = 'sha256:' + createHash('sha256').update(raw).digest('hex');
    if (actual !== attestation.permissions_hash) return null;

    return parsed;
  } catch {
    return null;
  }
}

export function detectBackend(preferred?: EnforcementBackend | 'auto'): EnforcementBackend {
  if (preferred && preferred !== 'auto') return preferred;
  const os = platform();
  if (os === 'darwin') return 'darwin-sandbox';
  if (os === 'linux') return 'linux-landlock';
  return 'node-permissions';
}

export async function enforceAndRun(
  skillDir: string,
  command: string,
  args: string[],
  policy: PermissionsPolicy,
  config?: EnforcementConfig,
): Promise<EnforcementResult> {
  const start = performance.now();
  const timeout = config?.timeout ?? DEFAULT_TIMEOUT;
  const maxMemory = config?.maxMemory ?? DEFAULT_MAX_MEMORY;
  const backend = detectBackend(config?.backend);

  const baseEnv = safeEnv();
  const userEnv = config?.env ?? {};
  const memOpt = `--max-old-space-size=${maxMemory}`;
  const mergedEnv = { ...baseEnv, ...userEnv };

  let spawnPolicy: SpawnPolicy;
  let profilePath: string | undefined;

  if (backend === 'darwin-sandbox') {
    const result = await buildDarwinSandboxArgs(policy, command, args, mergedEnv);
    profilePath = result.profilePath;
    spawnPolicy = result;
    if (spawnPolicy.env.NODE_OPTIONS) {
      spawnPolicy.env.NODE_OPTIONS += ` ${memOpt}`;
    } else {
      spawnPolicy.env.NODE_OPTIONS = memOpt;
    }
  } else if (backend === 'linux-landlock') {
    spawnPolicy = buildLinuxLandlockArgs(policy, command, args, mergedEnv);
    spawnPolicy.env.NODE_OPTIONS += ` ${memOpt}`;
  } else {
    spawnPolicy = buildNodePermissionArgs(policy, command, args, mergedEnv);
    spawnPolicy.env.NODE_OPTIONS += ` ${memOpt}`;
  }

  const violations: EnforcementViolation[] = [];
  const onViolation = config?.onViolation;

  function pushViolation(v: EnforcementViolation) {
    violations.push(v);
    try { onViolation?.(v); } catch { /* user callback must not crash enforcer */ }
  }

  try {
    const result = await spawnEnforced(
      spawnPolicy.command,
      spawnPolicy.args,
      spawnPolicy.env,
      config?.cwd ?? resolve(skillDir),
      timeout,
      pushViolation,
    );

    return {
      status: violations.length > 0 ? 'violation' : result.exitCode === 0 ? 'clean' : 'error',
      exitCode: result.exitCode,
      signal: result.signal,
      stdout: result.stdout,
      stderr: result.stderr,
      violations,
      backend,
      duration_ms: Math.round(performance.now() - start),
      enforced: spawnPolicy.enforced,
    };
  } finally {
    if (profilePath) await cleanupProfile(profilePath);
  }
}

interface SpawnResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  signal: string | null;
}

function spawnEnforced(
  command: string,
  args: string[],
  env: Record<string, string>,
  cwd: string,
  timeout: number,
  onViolation: (v: EnforcementViolation) => void,
): Promise<SpawnResult> {
  return new Promise<SpawnResult>((resolvePromise) => {
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const maxOutput = 1_000_000;

    const child = spawn(command, args, {
      cwd,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    child.stdout?.on('data', (data: Buffer) => {
      if (stdout.length < maxOutput) stdout += data.toString();
    });

    child.stderr?.on('data', (data: Buffer) => {
      const chunk = data.toString();
      if (stderr.length < maxOutput) stderr += chunk;
      detectViolations(chunk, onViolation);
    });

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      setTimeout(() => { if (!child.killed) child.kill('SIGKILL'); }, 3000);
      onViolation({
        type: 'timeout',
        severity: 'high',
        message: `Process exceeded ${timeout}ms timeout`,
        timestamp: Date.now(),
      });
    }, timeout);

    child.on('close', (code, signal) => {
      clearTimeout(timer);

      if (signal === 'SIGKILL' && !timedOut) {
        onViolation({
          type: 'memory',
          severity: 'high',
          message: 'Process killed (possible OOM)',
          timestamp: Date.now(),
        });
      }

      resolvePromise({
        stdout: stdout.slice(0, maxOutput),
        stderr: stderr.slice(0, maxOutput),
        exitCode: code,
        signal,
      });
    });

    child.on('error', (err) => {
      clearTimeout(timer);
      onViolation({
        type: 'crash',
        severity: 'high',
        message: `Process error: ${err.message}`,
        timestamp: Date.now(),
      });
      resolvePromise({
        stdout, stderr,
        exitCode: null,
        signal: null,
      });
    });
  });
}

function detectViolations(
  output: string,
  onViolation: (v: EnforcementViolation) => void,
): void {
  if (output.includes('ERR_ACCESS_DENIED')) {
    const type = classifyAccessDenied(output);
    onViolation({
      type,
      severity: 'critical',
      message: `Permission denied: ${type}`,
      detail: output.slice(0, 500),
      timestamp: Date.now(),
    });
  }

  if (output.includes('EACCES') || output.includes('EPERM')) {
    onViolation({
      type: classifyErrno(output),
      severity: 'critical',
      message: 'OS-level permission denied',
      detail: output.slice(0, 500),
      timestamp: Date.now(),
    });
  }

  if (output.includes('Operation not permitted')) {
    onViolation({
      type: 'exec',
      severity: 'critical',
      message: 'Sandbox blocked operation',
      detail: output.slice(0, 500),
      timestamp: Date.now(),
    });
  }
}

function classifyAccessDenied(
  output: string,
): EnforcementViolation['type'] {
  if (output.includes('FileSystemRead') || output.includes('fs.read')) return 'filesystem_read';
  if (output.includes('FileSystemWrite') || output.includes('fs.write')) return 'filesystem_write';
  if (output.includes('ChildProcess') || output.includes('child_process')) return 'exec';
  if (output.includes('NetConnect') || output.includes('net.connect')) return 'network';
  return 'exec';
}

function classifyErrno(output: string): EnforcementViolation['type'] {
  if (output.includes('open') || output.includes('read')) return 'filesystem_read';
  if (output.includes('write') || output.includes('mkdir')) return 'filesystem_write';
  if (output.includes('connect') || output.includes('socket')) return 'network';
  return 'exec';
}

function safeEnv(): Record<string, string> {
  const safe: Record<string, string> = {};
  const allow = ['PATH', 'HOME', 'USER', 'LANG', 'TERM'];
  for (const key of allow) {
    if (process.env[key]) safe[key] = process.env[key]!;
  }
  return safe;
}
