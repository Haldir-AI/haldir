import { describe, it, expect } from 'vitest';
import { analyzeOutput } from '../analyzer.js';
import type { ProcessOutput, PermissionsJson } from '../types.js';

const okProcess: ProcessOutput = {
  stdout: '',
  stderr: '',
  exitCode: 0,
  signal: null,
  timedOut: false,
};

describe('analyzeOutput', () => {
  it('no violations for clean output', () => {
    const violations = analyzeOutput(okProcess, null);
    expect(violations).toHaveLength(0);
  });

  it('detects network activity when not declared', () => {
    const proc = { ...okProcess, stdout: 'fetch("https://example.com")' };
    const violations = analyzeOutput(proc, null);
    expect(violations.some(v => v.type === 'network')).toBe(true);
  });

  it('no network violation when network declared', () => {
    const proc = { ...okProcess, stdout: 'fetch("https://example.com")' };
    const violations = analyzeOutput(proc, { network: true });
    expect(violations.some(v => v.type === 'network')).toBe(false);
  });

  it('no network violation when network is array', () => {
    const proc = { ...okProcess, stdout: 'fetch("https://api.com")' };
    const violations = analyzeOutput(proc, { network: ['api.com'] });
    expect(violations.some(v => v.type === 'network')).toBe(false);
  });

  it('detects exec when not declared', () => {
    const proc = { ...okProcess, stdout: 'const cp = require("child_process")' };
    const violations = analyzeOutput(proc, null);
    expect(violations.some(v => v.type === 'exec')).toBe(true);
  });

  it('detects subprocess in stderr', () => {
    const proc = { ...okProcess, stderr: 'spawn("/bin/sh")' };
    const violations = analyzeOutput(proc, null);
    expect(violations.some(v => v.type === 'exec')).toBe(true);
  });

  it('no exec violation when exec declared', () => {
    const proc = { ...okProcess, stdout: 'execSync("ls")' };
    const violations = analyzeOutput(proc, { exec: true });
    expect(violations.some(v => v.type === 'exec')).toBe(false);
  });

  it('detects EACCES in stderr', () => {
    const proc = {
      ...okProcess,
      exitCode: 1,
      stderr: 'Error: EACCES: permission denied, open /etc/shadow',
    };
    const violations = analyzeOutput(proc, null);
    expect(violations.some(v => v.type === 'filesystem_write')).toBe(true);
  });

  it('detects EPERM in stderr', () => {
    const proc = {
      ...okProcess,
      exitCode: 1,
      stderr: 'Error: EPERM: operation not permitted',
    };
    const violations = analyzeOutput(proc, null);
    expect(violations.some(v => v.type === 'filesystem_write')).toBe(true);
  });

  it('no filesystem violation on clean exit', () => {
    const violations = analyzeOutput(okProcess, null);
    expect(violations.some(v => v.type === 'filesystem_write')).toBe(false);
  });

  it('detects Python subprocess patterns', () => {
    const proc = { ...okProcess, stdout: 'os.system("rm -rf /")' };
    const violations = analyzeOutput(proc, null);
    expect(violations.some(v => v.type === 'exec')).toBe(true);
  });

  it('detects http URL in output', () => {
    const proc = { ...okProcess, stdout: 'downloading from https://evil.com/payload' };
    const violations = analyzeOutput(proc, null);
    expect(violations.some(v => v.type === 'network')).toBe(true);
  });
});
