import { stat } from 'node:fs/promises';
import { PATTERN_DB } from './patterns/index.js';
import { walkDirectory, readFileLines } from './file-reader.js';
import { matchLine, matchResultToFinding } from './matcher.js';
import { classifyFile, applyContextAwareness, scanForSuspiciousUnicode } from './context.js';
import { scanManifest } from './manifest.js';
import { analyzeFileAST } from './ast-analyzer.js';
import type { ScanResult, ScanConfig, Finding, ASTFinding, Severity, ThreatCategory, ThreatPattern, ScanSummary, ContextualFinding } from './types.js';
import { DEFAULT_SKIP_DIRS, DEFAULT_MAX_FILES, DEFAULT_MAX_FILE_SIZE, SEVERITY_ORDER, AST_EXTENSIONS } from './types.js';

// Multiline patterns — cross-line dataflow that line-by-line regex cannot catch.
// Kept intentionally small: only high-confidence, high-severity patterns.
const MULTILINE_PATTERNS: Array<{
  id: string;
  category: ThreatCategory;
  severity: Severity;
  name: string;
  description: string;
  regex: RegExp;
}> = [
  {
    id: 'multiline_fetch_eval',
    category: 'supply_chain',
    severity: 'critical',
    name: 'Remote code fetch + eval (multiline)',
    description: 'Fetches remote code via HTTP and evaluates it — classic supply chain attack pattern',
    regex: /https?\.(get|request)\s*\([^)]*\)[\s\S]{0,500}eval\s*\(/,
  },
  {
    id: 'multiline_fetch_function',
    category: 'supply_chain',
    severity: 'critical',
    name: 'Remote code fetch + Function constructor (multiline)',
    description: 'Fetches remote code via HTTP and executes via Function constructor',
    regex: /https?\.(get|request)\s*\([^)]*\)[\s\S]{0,500}new\s+Function\s*\(/,
  },
  {
    id: 'multiline_read_exfil',
    category: 'exfiltration',
    severity: 'high',
    name: 'File read + network exfiltration (multiline)',
    description: 'Reads sensitive files and sends contents over the network',
    regex: /readFileSync\s*\([^)]*(?:\.ssh|\.aws|\.env|passwd|shadow|credentials)[^)]*\)[\s\S]{0,500}https?\.(request|get)\s*\(/,
  },
];

export async function scanDirectory(
  dirPath: string,
  config?: ScanConfig
): Promise<ScanResult> {
  const start = performance.now();

  const st = await stat(dirPath).catch(() => null);
  if (!st || !st.isDirectory()) {
    return emptyResult('pass', 0, 0, 0, performance.now() - start, config?.enableContextAwareness ?? false);
  }

  const patterns = config?.patterns ?? PATTERN_DB as unknown as ThreatPattern[];
  const skipDirs = config?.skipDirs ?? DEFAULT_SKIP_DIRS;
  const maxFiles = config?.maxFiles ?? DEFAULT_MAX_FILES;
  const maxFileSize = config?.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
  const severityThreshold = config?.severityThreshold ?? 'low';
  const thresholdOrder = SEVERITY_ORDER[severityThreshold];

  const extensionMap = buildExtensionMap(patterns);

  const { files, skippedCount } = await walkDirectory(dirPath, skipDirs, maxFiles, maxFileSize);

  const findings: Array<Finding | ContextualFinding> = [];
  const testFindings: Array<Finding | ContextualFinding> = [];
  let filesScanned = 0;

  // Context awareness settings
  const enableContext = config?.enableContextAwareness ?? false;
  const includeTestFindings = config?.includeTestFindings ?? false;
  const declaredCapabilities = config?.declaredCapabilities ?? [];

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

    // Structural manifest checks for package.json files
    if (file.relativePath.endsWith('package.json')) {
      const fullContent = lines.join('\n');
      const manifestFindings = scanManifest(fullContent, file.relativePath);
      for (const mf of manifestFindings) {
        if (SEVERITY_ORDER[mf.severity] >= thresholdOrder) {
          if (enableContext) {
            const fileClass = classifyFile(file.relativePath);
            const contextual = applyContextAwareness(mf, fileClass, declaredCapabilities);
            findings.push(contextual);
          } else {
            findings.push(mf);
          }
        }
      }
    }

    // Classify file for context awareness
    const fileClass = enableContext ? classifyFile(file.relativePath) : 'production';

    // FIX #1: Grapheme-aware Unicode scanning (if context enabled)
    // Check for suspicious Unicode BEFORE line-by-line pattern matching
    if (enableContext) {
      const fullContent = lines.join('\n');
      const hasSuspiciousUnicode = scanForSuspiciousUnicode(fullContent, file.relativePath);

      if (hasSuspiciousUnicode) {
        // Create a synthetic finding for suspicious Unicode
        const unicodeFinding: Finding = {
          pattern_id: 'hidden_text_unicode_contextual',
          category: 'prompt_injection',
          severity: 'critical',
          file: file.relativePath,
          line: 1, // We don't know exact line without more detail
          column: 0,
          match: '[hidden Unicode character]',
          context: '[grapheme-aware scan detected suspicious Unicode]',
          message: 'Suspicious hidden Unicode character detected (not part of emoji sequence)',
        };

        const contextual = applyContextAwareness(unicodeFinding, fileClass, declaredCapabilities);

        if (fileClass === 'test') {
          if (includeTestFindings) {
            testFindings.push(contextual);
          }
        } else {
          findings.push(contextual);
        }
      }
    }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line.trim()) continue;

      const matches = matchLine(line, i + 1, applicablePatterns);
      for (const m of matches) {
        const pattern = applicablePatterns.find(p => p.id === m.patternId)!;
        if (SEVERITY_ORDER[pattern.severity] < thresholdOrder) continue;

        const finding = matchResultToFinding(m, pattern, file.relativePath);

        // Apply context awareness if enabled
        if (enableContext) {
          const contextual = applyContextAwareness(finding, fileClass, declaredCapabilities);

          // FIX #2: Test findings preserve context metadata
          // Test findings go to separate channel WITH full contextual data
          if (fileClass === 'test') {
            if (includeTestFindings) {
              testFindings.push(contextual);
            }
            // Don't add to main findings
            continue;
          }

          // Use adjusted severity for status determination
          const effectiveSeverity = contextual.adjustedSeverity;
          if (SEVERITY_ORDER[effectiveSeverity] < thresholdOrder) continue;

          // Store full ContextualFinding with structured metadata
          findings.push(contextual);

          if (config?.stopOnFirstCritical && effectiveSeverity === 'critical') {
            return buildResult(findings, testFindings, filesScanned, skippedCount, patterns.length, performance.now() - start, enableContext);
          }
        } else {
          // No context awareness - use original behavior
          findings.push(finding);

          if (config?.stopOnFirstCritical && pattern.severity === 'critical') {
            return buildResult(findings, testFindings, filesScanned, skippedCount, patterns.length, performance.now() - start, enableContext);
          }
        }
      }
    }

    // Multiline pattern pass — catches cross-line dataflow that line-by-line misses.
    // Intentionally small and targeted: only patterns with high confidence.
    if (['js', 'ts', 'jsx', 'tsx'].includes(file.extension)) {
      const fullContent = lines.join('\n');
      for (const mp of MULTILINE_PATTERNS) {
        const match = mp.regex.exec(fullContent);
        if (match) {
          const lineNum = fullContent.substring(0, match.index).split('\n').length;
          const finding: Finding = {
            pattern_id: mp.id,
            category: mp.category,
            severity: mp.severity,
            file: file.relativePath,
            line: lineNum,
            column: 0,
            match: match[0].substring(0, 120),
            context: mp.name,
            message: mp.description,
          };

          if (enableContext) {
            const contextual = applyContextAwareness(finding, fileClass, declaredCapabilities);
            if (fileClass === 'test') {
              if (includeTestFindings) testFindings.push(contextual);
            } else if (SEVERITY_ORDER[contextual.adjustedSeverity] >= thresholdOrder) {
              findings.push(contextual);
            }
          } else if (SEVERITY_ORDER[mp.severity] >= thresholdOrder) {
            findings.push(finding);
          }
        }
      }
    }

    // AST analysis pass — semantic checks that regex cannot express.
    // Opt-in: only runs when enableASTAnalysis is true.
    if (config?.enableASTAnalysis && AST_EXTENSIONS.includes(file.extension)) {
      const fullContent = lines.join('\n');
      const astFindings = analyzeFileAST(fullContent, file.relativePath, file.extension);
      for (const af of astFindings) {
        if (SEVERITY_ORDER[af.severity] < thresholdOrder) continue;

        // Deduplicate: if regex already found same file+line+category, boost confidence instead of adding duplicate
        const existingIdx = findings.findIndex(f => f.file === af.file && f.line === af.line && f.category === af.category);
        if (existingIdx >= 0) {
          // Boost existing finding by attaching AST confidence
          const existing = findings[existingIdx] as Finding & { confidence?: number; recommendation?: string };
          existing.confidence = Math.min(1.0, Math.max(existing.confidence ?? 0.6, af.confidence) + 0.05);
          existing.recommendation = af.recommendation;
          continue;
        }

        if (enableContext) {
          if (fileClass === 'test') {
            if (includeTestFindings) testFindings.push(af);
            continue;
          }
          findings.push(af);
        } else {
          findings.push(af);
        }
      }
    }
  }

  return buildResult(findings, testFindings, filesScanned, skippedCount, patterns.length, performance.now() - start, enableContext);
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
  findings: Array<Finding | ContextualFinding>,
  testFindings: Array<Finding | ContextualFinding>,
  filesScanned: number,
  filesSkipped: number,
  patternsChecked: number,
  durationMs: number,
  contextEnabled: boolean
): ScanResult {
  const summary = computeSummary(findings);
  const status = summary.critical > 0 ? 'reject'
    : (summary.high > 0 || summary.medium > 0) ? 'flag'
    : 'pass';

  const result: ScanResult = {
    status,
    duration_ms: Math.round(durationMs * 100) / 100,
    files_scanned: filesScanned,
    files_skipped: filesSkipped,
    patterns_checked: patternsChecked,
    findings,
    summary,
  };

  // Add optional fields if context awareness is enabled
  if (contextEnabled) {
    result.context_enabled = true;
    if (testFindings.length > 0) {
      result.test_findings = testFindings;
    }
  }

  return result;
}

function computeSummary(findings: Array<Finding | ContextualFinding>): ScanSummary {
  const summary: ScanSummary = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    // Use adjustedSeverity for ContextualFinding, severity for Finding
    const severity = 'adjustedSeverity' in f ? f.adjustedSeverity : f.severity;
    summary[severity]++;
  }
  return summary;
}

function emptyResult(
  status: 'pass',
  filesScanned: number,
  filesSkipped: number,
  patternsChecked: number,
  durationMs: number,
  contextEnabled: boolean
): ScanResult {
  const result: ScanResult = {
    status,
    duration_ms: Math.round(durationMs * 100) / 100,
    files_scanned: filesScanned,
    files_skipped: filesSkipped,
    patterns_checked: patternsChecked,
    findings: [],
    summary: { critical: 0, high: 0, medium: 0, low: 0 },
  };

  if (contextEnabled) {
    result.context_enabled = true;
  }

  return result;
}
