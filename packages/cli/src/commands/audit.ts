import { auditDirectory } from '@haldir/auditor';
import type { AuditResult, AuditStatus, SkillType } from '@haldir/auditor';

interface AuditCommandOptions {
  json?: boolean;
  type?: string;
  noCve?: boolean;
}

export async function auditCommand(dir: string, opts: AuditCommandOptions): Promise<void> {
  const result = await auditDirectory(dir, {
    skillType: opts.type as SkillType | undefined,
    checkCves: !opts.noCve,
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
  low: '\x1b[90m',
};
const RESET = '\x1b[0m';

function printHumanReadable(result: AuditResult): void {
  console.log(`\nAudit: ${result.dependencies_count} deps, ${result.manifests_found.join(', ') || 'none'}, ${result.duration_ms}ms`);
  console.log(`Lockfile: ${result.lockfile_present ? 'yes' : 'no'}\n`);

  if (result.findings.length === 0) {
    console.log('  No findings.\n');
  } else {
    for (const f of result.findings) {
      const color = SEVERITY_COLORS[f.severity] ?? '';
      console.log(`  ${color}${f.severity.toUpperCase()}${RESET}  ${f.id}`);
      if (f.dependency) console.log(`  Package: ${f.dependency}`);
      if (f.file) console.log(`  File: ${f.file}`);
      console.log(`  ${f.message}\n`);
    }
  }

  console.log(`Summary: ${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium, ${result.summary.low} low`);
  const statusLabel = result.status === 'reject' ? '\x1b[31mREJECT\x1b[0m'
    : result.status === 'flag' ? '\x1b[33mFLAG\x1b[0m'
    : '\x1b[32mPASS\x1b[0m';
  console.log(`Status: ${statusLabel}\n`);
}
