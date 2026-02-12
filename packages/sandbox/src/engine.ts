import type { SandboxResult, SandboxConfig, SandboxViolation } from './types.js';
import { DEFAULT_TIMEOUT } from './types.js';
import { loadPermissions, permissionsToSandboxConfig } from './permissions.js';
import { detectEntrypoint } from './detect.js';
import { runInSandbox } from './runner.js';
import { analyzeOutput } from './analyzer.js';

export async function sandboxSkill(
  skillDir: string,
  config?: SandboxConfig,
): Promise<SandboxResult> {
  const start = performance.now();

  const permissions = await loadPermissions(skillDir);
  const permConfig = permissionsToSandboxConfig(permissions, skillDir);

  const mergedConfig: SandboxConfig = {
    timeout: config?.timeout ?? DEFAULT_TIMEOUT,
    maxMemory: config?.maxMemory,
    allowNetwork: config?.allowNetwork ?? permConfig.allowNetwork ?? false,
    allowedReadPaths: config?.allowedReadPaths ?? permConfig.allowedReadPaths,
    allowedWritePaths: config?.allowedWritePaths ?? permConfig.allowedWritePaths,
    env: config?.env,
    cwd: skillDir,
  };

  let command: string;
  let args: string[];

  if (config?.entrypoint) {
    const parts = config.entrypoint.split(/\s+/);
    const first = parts[0];
    if (first.endsWith('.js') || first.endsWith('.mjs') || first.endsWith('.cjs')) {
      command = process.execPath;
      args = [...parts, ...(config.entrypointArgs ?? [])];
    } else if (first.endsWith('.py')) {
      command = 'python3';
      args = [...parts, ...(config.entrypointArgs ?? [])];
    } else if (first.endsWith('.sh')) {
      command = 'sh';
      args = [...parts, ...(config.entrypointArgs ?? [])];
    } else {
      command = first;
      args = [...parts.slice(1), ...(config.entrypointArgs ?? [])];
    }
  } else {
    const detected = await detectEntrypoint(skillDir);
    command = detected.command;
    args = detected.args;
  }

  const runResult = await runInSandbox(command, args, mergedConfig);
  const outputViolations = analyzeOutput(runResult.process, permissions);
  const allViolations = [...runResult.violations, ...outputViolations];

  const summary = computeSummary(allViolations);
  const status = summary.critical > 0 ? 'reject'
    : (summary.high > 0) ? 'flag'
    : 'pass';

  return {
    status,
    duration_ms: Math.round(performance.now() - start),
    process: runResult.process,
    violations: allViolations,
    summary,
  };
}

function computeSummary(violations: SandboxViolation[]) {
  const summary = { critical: 0, high: 0, medium: 0 };
  for (const v of violations) summary[v.severity]++;
  return summary;
}
