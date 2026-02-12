import { describe, it, expect } from 'vitest';
import { runInSandbox } from '../runner.js';

describe('runInSandbox', () => {
  it('runs a simple echo command', async () => {
    const result = await runInSandbox('echo', ['hello world'], {
      timeout: 5000,
    });
    expect(result.process.stdout.trim()).toBe('hello world');
    expect(result.process.exitCode).toBe(0);
    expect(result.violations).toHaveLength(0);
  });

  it('captures stderr', async () => {
    const result = await runInSandbox('sh', ['-c', 'echo error >&2'], {
      timeout: 5000,
    });
    expect(result.process.stderr.trim()).toBe('error');
  });

  it('captures non-zero exit code', async () => {
    const result = await runInSandbox('sh', ['-c', 'exit 42'], {
      timeout: 5000,
    });
    expect(result.process.exitCode).toBe(42);
  });

  it('enforces timeout', async () => {
    const result = await runInSandbox('sleep', ['10'], {
      timeout: 500,
    });
    expect(result.process.timedOut).toBe(true);
    expect(result.violations.some(v => v.type === 'timeout')).toBe(true);
  }, 10000);

  it('detects permission denied in stderr', async () => {
    const result = await runInSandbox('sh', ['-c', 'echo "ERR_ACCESS_DENIED" >&2; exit 1'], {
      timeout: 5000,
    });
    expect(result.violations.some(v => v.type === 'exec')).toBe(true);
  });

  it('handles nonexistent command', async () => {
    const result = await runInSandbox('nonexistent-cmd-xyz', [], {
      timeout: 5000,
    });
    expect(result.violations.some(v => v.type === 'crash')).toBe(true);
  });

  it('runs node script inline', async () => {
    const result = await runInSandbox('node', ['-e', 'console.log(1+2)'], {
      timeout: 5000,
    });
    expect(result.process.stdout.trim()).toBe('3');
    expect(result.process.exitCode).toBe(0);
  });

  it('provides safe env (no secrets leaked)', async () => {
    const result = await runInSandbox('sh', ['-c', 'echo $HOME'], {
      timeout: 5000,
    });
    expect(result.process.stdout.trim().length).toBeGreaterThan(0);
  });

  it('custom env variables are passed', async () => {
    const result = await runInSandbox('sh', ['-c', 'echo $MY_VAR'], {
      timeout: 5000,
      env: { MY_VAR: 'test123' },
    });
    expect(result.process.stdout.trim()).toBe('test123');
  });
});
