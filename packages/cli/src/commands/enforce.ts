import { resolve, relative, isAbsolute } from 'node:path';
import {
  loadPermissions,
  compilePolicy,
  enforceAndRun,
  detectBackend,
} from '@haldir/enforcer';
import type { EnforcementResult, EnforcementViolation, EnforcementBackend } from '@haldir/enforcer';

const RESET = '\x1b[0m';

interface EnforceCommandOptions {
  json?: boolean;
  backend?: string;
  timeout?: string;
  entrypoint?: string;
  args?: string[];
}

export async function enforceCommand(dir: string, opts: EnforceCommandOptions): Promise<void> {
  const skillDir = resolve(dir);
  const perms = await loadPermissions(skillDir);

  if (!perms) {
    console.error('No .vault/permissions.json found — cannot enforce.');
    process.exit(2);
  }

  const policy = compilePolicy(perms, skillDir);
  const backend = (opts.backend as EnforcementBackend) ?? 'auto';
  const timeout = opts.timeout ? parseInt(opts.timeout, 10) : undefined;

  const entrypoint = opts.entrypoint ?? detectEntrypoint(skillDir);
  if (!entrypoint) {
    console.error('No entrypoint found. Use --entrypoint to specify.');
    process.exit(2);
  }

  const resolvedEntry = resolve(skillDir, entrypoint);
  const rel = relative(skillDir, resolvedEntry);
  if (rel.startsWith('..') || isAbsolute(rel)) {
    console.error('Error: --entrypoint must resolve within the skill directory');
    process.exit(2);
  }

  const command = process.execPath;
  const args = [resolvedEntry, ...(opts.args ?? [])];

  const result = await enforceAndRun(skillDir, command, args, policy, {
    backend: detectBackend(backend),
    timeout,
    onViolation: (v) => {
      if (!opts.json) {
        const color = v.severity === 'critical' ? '\x1b[31m' : v.severity === 'high' ? '\x1b[33m' : '\x1b[36m';
        console.error(`  ${color}VIOLATION${RESET}  ${v.type}: ${v.message}`);
      }
    },
  });

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printHumanReadable(result);
  }

  if (result.status === 'violation') process.exit(1);
  if (result.status === 'error') process.exit(2);
}

function printHumanReadable(result: EnforcementResult): void {
  console.log(`\nEnforcement: ${result.duration_ms}ms, backend=${result.backend}, exit=${result.exitCode ?? 'null'}\n`);

  console.log(`  Enforced: filesystem=${result.enforced.filesystem}, network=${result.enforced.network}, exec=${result.enforced.exec}\n`);

  if (result.violations.length === 0) {
    console.log('  No violations.\n');
  } else {
    console.log(`  ${result.violations.length} violation(s):\n`);
    for (const v of result.violations) {
      const color = v.severity === 'critical' ? '\x1b[31m' : v.severity === 'high' ? '\x1b[33m' : '\x1b[36m';
      console.log(`  ${color}${v.severity.toUpperCase()}${RESET}  ${v.type}`);
      console.log(`    ${v.message}`);
      if (v.detail) console.log(`    ${v.detail.slice(0, 200)}`);
      console.log('');
    }
  }

  const statusLabel = result.status === 'violation' ? '\x1b[31mVIOLATION\x1b[0m'
    : result.status === 'error' ? '\x1b[33mERROR\x1b[0m'
    : '\x1b[32mCLEAN\x1b[0m';
  console.log(`Status: ${statusLabel}\n`);
}

function detectEntrypoint(skillDir: string): string | null {
  const candidates = ['index.js', 'index.mjs', 'main.js', 'server.js', 'app.js'];
  for (const c of candidates) {
    try {
      require.resolve(resolve(skillDir, c));
      return c;
    } catch { /* continue */ }
  }
  return null;
}
