import { spawn } from 'node:child_process';
import { platform } from 'node:os';
import type { ProcessOutput, SandboxConfig, SandboxViolation } from './types.js';
import { DEFAULT_TIMEOUT, DEFAULT_MAX_MEMORY } from './types.js';

export interface RunResult {
  process: ProcessOutput;
  violations: SandboxViolation[];
}

export async function runInSandbox(
  command: string,
  args: string[],
  config: SandboxConfig,
): Promise<RunResult> {
  const timeout = config.timeout ?? DEFAULT_TIMEOUT;
  const maxMemory = config.maxMemory ?? DEFAULT_MAX_MEMORY;

  const env: Record<string, string> = {
    ...safeEnv(),
    ...(config.env ?? {}),
    NODE_OPTIONS: `--max-old-space-size=${maxMemory}`,
  };

  return new Promise<RunResult>((resolve) => {
    const violations: SandboxViolation[] = [];
    let stdout = '';
    let stderr = '';
    let timedOut = false;

    const child = spawn(command, args, {
      cwd: config.cwd,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout,
    });

    const maxOutput = 1_000_000;

    child.stdout?.on('data', (data: Buffer) => {
      if (stdout.length < maxOutput) stdout += data.toString();
    });

    child.stderr?.on('data', (data: Buffer) => {
      if (stderr.length < maxOutput) stderr += data.toString();
      analyzeStderr(data.toString(), violations);
    });

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
      violations.push({
        type: 'timeout',
        severity: 'high',
        message: `Process exceeded ${timeout}ms timeout`,
      });
    }, timeout);

    child.on('close', (code, signal) => {
      clearTimeout(timer);

      if (signal === 'SIGKILL' && !timedOut) {
        violations.push({
          type: 'memory',
          severity: 'high',
          message: 'Process killed (possible OOM)',
        });
      }

      if (code !== null && code !== 0 && !timedOut) {
        const crashDetail = stderr.slice(-500);
        if (crashDetail.includes('ERR_ACCESS_DENIED')) {
          violations.push({
            type: 'exec',
            severity: 'critical',
            message: 'Permission denied — attempted unauthorized operation',
            detail: crashDetail,
          });
        }
      }

      resolve({
        process: {
          stdout: stdout.slice(0, maxOutput),
          stderr: stderr.slice(0, maxOutput),
          exitCode: code,
          signal,
          timedOut,
        },
        violations,
      });
    });

    child.on('error', (err) => {
      clearTimeout(timer);
      violations.push({
        type: 'crash',
        severity: 'high',
        message: `Process error: ${err.message}`,
      });
      resolve({
        process: {
          stdout, stderr,
          exitCode: null,
          signal: null,
          timedOut: false,
        },
        violations,
      });
    });
  });
}

function safeEnv(): Record<string, string> {
  const safe: Record<string, string> = {};
  const allow = ['PATH', 'HOME', 'USER', 'LANG', 'TERM', 'NODE_PATH', 'PYTHONPATH'];
  for (const key of allow) {
    if (process.env[key]) safe[key] = process.env[key]!;
  }
  return safe;
}

function analyzeStderr(output: string, violations: SandboxViolation[]): void {
  if (output.includes('ERR_ACCESS_DENIED')) {
    violations.push({
      type: 'exec',
      severity: 'critical',
      message: 'Node.js permission model denied access',
      detail: output.slice(0, 200),
    });
  }

  if (output.includes('ECONNREFUSED') || output.includes('ENOTFOUND') || output.includes('getaddrinfo')) {
    violations.push({
      type: 'network',
      severity: 'medium',
      message: 'Attempted network connection',
      detail: output.slice(0, 200),
    });
  }
}
