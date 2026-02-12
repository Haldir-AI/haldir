import type { AuditFinding, SkillType, Dependency } from '../types.js';
import { DEFAULT_MAX_DEPS_SKILL_MD, DEFAULT_MAX_DEPS_MCP } from '../types.js';

export function checkDependencyCount(
  deps: Dependency[],
  skillType: SkillType,
  maxSkillMd?: number,
  maxMcp?: number,
): AuditFinding[] {
  const findings: AuditFinding[] = [];
  const limit = skillType === 'skill.md'
    ? (maxSkillMd ?? DEFAULT_MAX_DEPS_SKILL_MD)
    : (maxMcp ?? DEFAULT_MAX_DEPS_MCP);

  if (deps.length > limit) {
    findings.push({
      id: 'high_dep_count',
      severity: 'medium',
      category: 'high_count',
      message: `${deps.length} dependencies exceeds limit of ${limit} for ${skillType} skills`,
    });
  }

  return findings;
}
