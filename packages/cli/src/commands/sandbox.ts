import { sandboxSkill } from '@haldir/sandbox';
import type { SandboxResult, SandboxViolation } from '@haldir/sandbox';

interface SandboxCommandOptions {
  json?: boolean;
  timeout?: string;
  entrypoint?: string;
}

export async function sandboxCommand(dir: string, opts: SandboxCommandOptions): Promise<void> {
  const result = await sandboxSkill(dir, {
    timeout: opts.timeout ? parseInt(opts.timeout, 10) : undefined,
    entrypoint: opts.entrypoint,
  });

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printHumanReadable(result);
  }

  if (result.status === 'reject') process.exit(1);
  if (result.status === 'flag') process.exit(1);
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '\x1b[31m',
  high: '\x1b[33m',
  medium: '\x1b[36m',
};
const RESET = '\x1b[0m';

function printHumanReadable(result: SandboxResult): void {
  console.log(`\nSandbox: ${result.duration_ms}ms, exit=${result.process.exitCode ?? 'null'}, timedOut=${result.process.timedOut}\n`);

  if (result.violations.length === 0) {
    console.log('  No violations.\n');
  } else {
    for (const v of result.violations) {
      const color = SEVERITY_COLORS[v.severity] ?? '';
      console.log(`  ${color}${v.severity.toUpperCase()}${RESET}  ${v.type}`);
      console.log(`  ${v.message}`);
      if (v.detail) console.log(`  Detail: ${v.detail.slice(0, 100)}`);
      console.log('');
    }
  }

  const statusLabel = result.status === 'reject' ? '\x1b[31mREJECT\x1b[0m'
    : result.status === 'flag' ? '\x1b[33mFLAG\x1b[0m'
    : '\x1b[32mPASS\x1b[0m';
  console.log(`Summary: ${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium`);
  console.log(`Status: ${statusLabel}\n`);
}
