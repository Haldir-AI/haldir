import { scanDirectory, PATTERN_DB, deserializeBundle } from '@haldir/scanner';
import type { Severity, ScanResult, ThreatPattern } from '@haldir/scanner';
import { getCachedBundle, getStaleCachedBundle, cacheBundle } from '../cache.js';
import { fetchPatternBundle } from '../registry-client.js';

export interface ScanCommandOptions {
  severity?: string;
  json?: boolean;
  strict?: boolean;
  ast?: boolean;
  context?: boolean;
  registry?: string;
  patternVersion?: string;
  offline?: boolean;
}

export async function resolvePatterns(opts: ScanCommandOptions): Promise<{
  patterns: ThreatPattern[];
  source: string;
  version: string;
}> {
  if (opts.offline) {
    const cached = await getCachedBundle(opts.patternVersion);
    if (cached) {
      return { patterns: deserializeBundle(cached), source: 'cache (offline)', version: cached.version };
    }
    const stale = await getStaleCachedBundle(opts.patternVersion);
    if (stale) {
      return { patterns: deserializeBundle(stale), source: 'cache (offline, stale)', version: stale.version };
    }
    return { patterns: [...PATTERN_DB], source: 'built-in', version: 'built-in' };
  }

  if (!opts.registry) {
    return { patterns: [...PATTERN_DB], source: 'built-in', version: 'built-in' };
  }

  const cached = await getCachedBundle(opts.patternVersion);
  if (cached) {
    return { patterns: deserializeBundle(cached), source: 'cache', version: cached.version };
  }

  try {
    const bundle = await fetchPatternBundle(opts.registry, opts.patternVersion);
    await cacheBundle(bundle);
    return { patterns: deserializeBundle(bundle), source: 'registry', version: bundle.version };
  } catch {
    const stale = await getStaleCachedBundle(opts.patternVersion);
    if (stale) {
      console.error(`Warning: Registry unreachable, using stale cache (v${stale.version})`);
      return { patterns: deserializeBundle(stale), source: 'cache (stale)', version: stale.version };
    }
    console.error('Warning: Registry unreachable, using built-in patterns');
    return { patterns: [...PATTERN_DB], source: 'built-in', version: 'built-in' };
  }
}

export async function scanCommand(dir: string, opts: ScanCommandOptions): Promise<void> {
  const severityThreshold = (opts.severity ?? 'low') as Severity;
  const { patterns, source, version } = await resolvePatterns(opts);

  const result = await scanDirectory(dir, {
    severityThreshold,
    patterns,
    enableASTAnalysis: opts.ast ?? false,
    enableContextAwareness: opts.context ?? false,
  });

  if (opts.json) {
    console.log(JSON.stringify({ ...result, patternSource: source, patternVersion: version }, null, 2));
  } else {
    if (source !== 'built-in') {
      console.log(`Patterns: v${version} (${source})`);
    }
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
      const ast = 'confidence' in f ? ` [confidence=${(f as any).confidence} ${(f as any).recommendation}]` : '';
      console.log(`  ${color}${f.severity.toUpperCase()}${RESET}  ${f.pattern_id}${ast}`);
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
