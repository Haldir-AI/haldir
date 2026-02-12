import type { ThreatPattern, Finding } from './types.js';

export interface MatchResult {
  patternId: string;
  line: number;
  column: number;
  match: string;
  context: string;
}

const regexCache = new WeakMap<RegExp, RegExp>();

function getCachedRegex(source: RegExp): RegExp {
  let cached = regexCache.get(source);
  if (!cached) {
    cached = new RegExp(source.source, source.flags);
    regexCache.set(source, cached);
  }
  return cached;
}

export function matchLine(
  line: string,
  lineNumber: number,
  patterns: ThreatPattern[]
): MatchResult[] {
  const results: MatchResult[] = [];
  for (const pattern of patterns) {
    const re = getCachedRegex(pattern.regex);
    re.lastIndex = 0;
    const m = re.exec(line);
    if (m) {
      results.push({
        patternId: pattern.id,
        line: lineNumber,
        column: m.index,
        match: m[0],
        context: line,
      });
    }
  }
  return results;
}

export function matchResultToFinding(
  result: MatchResult,
  pattern: ThreatPattern,
  relativePath: string
): Finding {
  return {
    pattern_id: result.patternId,
    category: pattern.category,
    severity: pattern.severity,
    file: relativePath,
    line: result.line,
    column: result.column,
    match: result.match,
    context: result.context,
    message: pattern.description,
  };
}
