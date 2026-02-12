import type { ProcessOutput, SandboxViolation, PermissionsJson } from './types.js';

const NETWORK_INDICATORS = [
  /fetch\s*\(/,
  /https?:\/\//,
  /net\.connect/,
  /socket\.connect/,
  /XMLHttpRequest/,
  /\.listen\(\d+\)/,
];

const FS_WRITE_INDICATORS = [
  /writeFile|writeFileSync/,
  /appendFile|appendFileSync/,
  /createWriteStream/,
  /fs\.write\(/,
];

const EXEC_INDICATORS = [
  /child_process/,
  /exec\(|execSync\(/,
  /spawn\(|spawnSync\(/,
  /subprocess\.run/,
  /os\.system\(/,
  /os\.popen\(/,
];

export function analyzeOutput(
  output: ProcessOutput,
  permissions: PermissionsJson | null,
): SandboxViolation[] {
  const violations: SandboxViolation[] = [];
  const combined = output.stdout + output.stderr;

  const decl = permissions?.declared ?? permissions;
  if (!decl?.network && !Array.isArray(decl?.network)) {
    for (const pattern of NETWORK_INDICATORS) {
      if (pattern.test(combined)) {
        violations.push({
          type: 'network',
          severity: 'high',
          message: `Network activity detected in output but not declared in permissions`,
          detail: combined.match(pattern)?.[0],
        });
        break;
      }
    }
  }

  if (!decl?.exec) {
    for (const pattern of EXEC_INDICATORS) {
      if (pattern.test(combined)) {
        violations.push({
          type: 'exec',
          severity: 'critical',
          message: `Subprocess execution detected but not declared in permissions`,
          detail: combined.match(pattern)?.[0],
        });
        break;
      }
    }
  }

  if (output.exitCode !== 0 && output.exitCode !== null && !output.timedOut) {
    const isPermDenied = output.stderr.includes('EACCES') ||
      output.stderr.includes('EPERM') ||
      output.stderr.includes('Permission denied');
    if (isPermDenied) {
      violations.push({
        type: 'filesystem_write',
        severity: 'high',
        message: 'Process attempted filesystem access that was denied',
        detail: output.stderr.slice(-200),
      });
    }
  }

  return violations;
}
