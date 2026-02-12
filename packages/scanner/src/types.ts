export type ThreatCategory =
  | 'exfiltration'
  | 'privilege_escalation'
  | 'supply_chain'
  | 'prompt_injection'
  | 'persistence'
  | 'campaign_indicator'
  | 'credential_exposure';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface Finding {
  pattern_id: string;
  category: ThreatCategory;
  severity: Severity;
  file: string;
  line: number;
  column: number;
  match: string;
  context: string;
  message: string;
}

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ScanResult {
  status: 'pass' | 'flag' | 'reject';
  duration_ms: number;
  files_scanned: number;
  files_skipped: number;
  patterns_checked: number;
  findings: Finding[];
  summary: ScanSummary;
}

export interface ScanConfig {
  maxFiles?: number;
  maxFileSize?: number;
  skipDirs?: string[];
  severityThreshold?: Severity;
  patterns?: ThreatPattern[];
  fileExtensions?: string[];
  stopOnFirstCritical?: boolean;
}

export interface ThreatPattern {
  id: string;
  category: ThreatCategory;
  severity: Severity;
  name: string;
  description: string;
  regex: RegExp;
  fileExtensions: string[];
}

export const DEFAULT_SKIP_DIRS = ['.vault', 'node_modules', '.git', '__pycache__', 'venv', '.venv'];
export const DEFAULT_MAX_FILES = 10_000;
export const DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

export const ALL_EXTENSIONS = ['py', 'js', 'ts', 'jsx', 'tsx', 'md', 'yaml', 'yml', 'json', 'sh', 'bash', 'zsh', 'rb', 'go', 'rs', 'toml', 'cfg', 'ini', 'env', 'txt'];
export const CODE_EXTENSIONS = ['py', 'js', 'ts', 'jsx', 'tsx', 'rb', 'go', 'rs', 'sh', 'bash', 'zsh'];
export const MARKDOWN_EXTENSIONS = ['md'];
export const CONFIG_EXTENSIONS = ['yaml', 'yml', 'json', 'toml', 'cfg', 'ini', 'env'];
