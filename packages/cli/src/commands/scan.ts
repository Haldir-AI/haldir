import { scanDirectory } from '@haldir/scanner';
import type { Severity, ScanResult } from '@haldir/scanner';

interface ScanCommandOptions {
  severity?: string;
  json?: boolean;
  strict?: boolean;
}

export async function scanCommand(dir: string, opts: ScanCommandOptions): Promise<void> {
  const severityThreshold = (opts.severity ?? 'low') as Severity;
  const result = await scanDirectory(dir, { severityThreshold });

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printHumanReadable(result);
  }

  if (result.status === 'reject') process.exit(1);
  if (result.status === 'flag' && opts.strict) process.exit(1);
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '\x1b[31m',
  high: '\x1b[33m',
  medium: '\x1b[36m',
  low: '\x1b[90m',
};
const RESET = '\x1b[0m';

function printHumanReadable(result: ScanResult): void {
  const { files_scanned, patterns_checked, duration_ms, findings, summary, status } = result;

  console.log(`\nScan: ${files_scanned} files, ${patterns_checked} patterns, ${duration_ms}ms\n`);

  if (findings.length === 0) {
    console.log('  No findings.\n');
  } else {
    for (const f of findings) {
      const color = SEVERITY_COLORS[f.severity] ?? '';
      console.log(`  ${color}${f.severity.toUpperCase()}${RESET}  ${f.pattern_id}`);
      console.log(`  ${f.file}:${f.line}:${f.column}  ${f.match}`);
      console.log(`  ${f.message}\n`);
    }
  }

  console.log(`Summary: ${summary.critical} critical, ${summary.high} high, ${summary.medium} medium, ${summary.low} low`);
  const statusLabel = status === 'reject' ? '\x1b[31mREJECT\x1b[0m'
    : status === 'flag' ? '\x1b[33mFLAG\x1b[0m'
    : '\x1b[32mPASS\x1b[0m';
  console.log(`Status: ${statusLabel}\n`);
}
