import type { AuditFinding } from '../types.js';
import { DEFAULT_MAX_DEPTH } from '../types.js';
import type { PackageLockDepth } from '../parsers/package-json.js';

export function checkDepth(
  depthInfo: PackageLockDepth | null,
  maxDepth?: number,
): AuditFinding[] {
  if (!depthInfo) return [];

  const limit = maxDepth ?? DEFAULT_MAX_DEPTH;
  const findings: AuditFinding[] = [];

  if (depthInfo.maxDepth > limit) {
    findings.push({
      id: 'deep_dep_tree',
      severity: 'medium',
      category: 'deep_tree',
      message: `Dependency tree depth ${depthInfo.maxDepth} exceeds limit of ${limit} levels`,
    });
  }

  return findings;
}
