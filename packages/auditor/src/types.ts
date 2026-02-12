export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type AuditStatus = 'pass' | 'flag' | 'reject';

export type ManifestType =
  | 'package.json'
  | 'requirements.txt'
  | 'pyproject.toml'
  | 'go.mod'
  | 'Cargo.toml';

export type SkillType = 'skill.md' | 'mcp';

export interface Dependency {
  name: string;
  version: string;
  pinned: boolean;
  hasHash: boolean;
  source: ManifestType;
}

export interface AuditFinding {
  id: string;
  severity: Severity;
  category: 'unpinned' | 'no_lockfile' | 'high_count' | 'deep_tree' | 'cve' | 'suspicious' | 'pep723';
  message: string;
  dependency?: string;
  file?: string;
  cve?: string;
}

export interface AuditSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface AuditResult {
  status: AuditStatus;
  duration_ms: number;
  manifests_found: ManifestType[];
  dependencies_count: number;
  lockfile_present: boolean;
  findings: AuditFinding[];
  summary: AuditSummary;
  dependencies: Dependency[];
}

export interface AuditConfig {
  skillType?: SkillType;
  maxDepsSkillMd?: number;
  maxDepsMcp?: number;
  maxDepthLevel?: number;
  checkCves?: boolean;
  advisoryTimeout?: number;
}

export const DEFAULT_MAX_DEPS_SKILL_MD = 20;
export const DEFAULT_MAX_DEPS_MCP = 50;
export const DEFAULT_MAX_DEPTH = 5;
export const DEFAULT_ADVISORY_TIMEOUT = 10_000;

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};
