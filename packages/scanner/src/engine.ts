import { stat } from 'node:fs/promises';
import { PATTERN_DB } from './patterns/index.js';
import { walkDirectory, readFileLines } from './file-reader.js';
import { matchLine, matchResultToFinding } from './matcher.js';
import type { ScanResult, ScanConfig, Finding, Severity, ThreatPattern, ScanSummary } from './types.js';
import { DEFAULT_SKIP_DIRS, DEFAULT_MAX_FILES, DEFAULT_MAX_FILE_SIZE, SEVERITY_ORDER } from './types.js';

export async function scanDirectory(
  dirPath: string,
  config?: ScanConfig
): Promise<ScanResult> {
  const start = performance.now();

  const st = await stat(dirPath).catch(() => null);
  if (!st || !st.isDirectory()) {
    return emptyResult('pass', 0, 0, 0, performance.now() - start);
  }

  const patterns = config?.patterns ?? PATTERN_DB as unknown as ThreatPattern[];
  const skipDirs = config?.skipDirs ?? DEFAULT_SKIP_DIRS;
  const maxFiles = config?.maxFiles ?? DEFAULT_MAX_FILES;
  const maxFileSize = config?.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
  const severityThreshold = config?.severityThreshold ?? 'low';
  const thresholdOrder = SEVERITY_ORDER[severityThreshold];

  const extensionMap = buildExtensionMap(patterns);

  const { files, skippedCount } = await walkDirectory(dirPath, skipDirs, maxFiles, maxFileSize);

  const findings: Finding[] = [];
  let filesScanned = 0;

  for (const file of files) {
    const applicablePatterns = extensionMap.get(file.extension);
    if (!applicablePatterns || applicablePatterns.length === 0) {
      continue;
    }

    const lines = await readFileLines(file.absolutePath);
    if (!lines) {
      continue;
    }

    filesScanned++;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line.trim()) continue;

      const matches = matchLine(line, i + 1, applicablePatterns);
      for (const m of matches) {
        const pattern = applicablePatterns.find(p => p.id === m.patternId)!;
        if (SEVERITY_ORDER[pattern.severity] < thresholdOrder) continue;

        findings.push(matchResultToFinding(m, pattern, file.relativePath));

        if (config?.stopOnFirstCritical && pattern.severity === 'critical') {
          return buildResult(findings, filesScanned, skippedCount, patterns.length, performance.now() - start);
        }
      }
    }
  }

  return buildResult(findings, filesScanned, skippedCount, patterns.length, performance.now() - start);
}

function buildExtensionMap(patterns: readonly ThreatPattern[]): Map<string, ThreatPattern[]> {
  const map = new Map<string, ThreatPattern[]>();
  for (const pattern of patterns) {
    for (const ext of pattern.fileExtensions) {
      const list = map.get(ext);
      if (list) {
        list.push(pattern);
      } else {
        map.set(ext, [pattern]);
      }
    }
  }
  return map;
}

function buildResult(
  findings: Finding[],
  filesScanned: number,
  filesSkipped: number,
  patternsChecked: number,
  durationMs: number
): ScanResult {
  const summary = computeSummary(findings);
  const status = summary.critical > 0 ? 'reject'
    : (summary.high > 0 || summary.medium > 0) ? 'flag'
    : 'pass';

  return {
    status,
    duration_ms: Math.round(durationMs * 100) / 100,
    files_scanned: filesScanned,
    files_skipped: filesSkipped,
    patterns_checked: patternsChecked,
    findings,
    summary,
  };
}

function computeSummary(findings: Finding[]): ScanSummary {
  const summary: ScanSummary = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    summary[f.severity]++;
  }
  return summary;
}

function emptyResult(
  status: 'pass',
  filesScanned: number,
  filesSkipped: number,
  patternsChecked: number,
  durationMs: number
): ScanResult {
  return {
    status,
    duration_ms: Math.round(durationMs * 100) / 100,
    files_scanned: filesScanned,
    files_skipped: filesSkipped,
    patterns_checked: patternsChecked,
    findings: [],
    summary: { critical: 0, high: 0, medium: 0, low: 0 },
  };
}
