export type ThreatCategory =
  | 'exfiltration'
  | 'privilege_escalation'
  | 'supply_chain'
  | 'prompt_injection'
  | 'persistence'
  | 'campaign_indicator'
  | 'credential_exposure'
  | 'obfuscation';

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

/**
 * File classification for context-aware analysis
 * Used to understand WHERE code is found, not to suppress severity
 */
export type FileClassification =
  | 'production'      // Main code files (.js, .ts, .py)
  | 'test'            // Test files (__tests__/, *.test.ts)
  | 'documentation'   // Docs (.md, README)
  | 'build'           // CI/CD (.github/workflows/)
  | 'configuration';  // Config files (.json, .yaml)

/**
 * Context-enhanced finding with dual severity
 * originalSeverity: Pattern's base severity
 * adjustedSeverity: After context analysis (NEVER lower for supply-chain)
 * contextReason: MANDATORY - why severity was adjusted
 * consentRequired: High-risk capability that needs explicit user consent
 */
export interface ContextualFinding extends Finding {
  originalSeverity: Severity;
  adjustedSeverity: Severity;
  fileClassification: FileClassification;
  contextReason: string; // MANDATORY
  consentRequired?: ConsentRequirement;
}

/**
 * High-risk capabilities that require explicit user consent
 * Even when "expected" for a skill type, these remain high-risk
 */
export interface ConsentRequirement {
  capability: string;        // e.g., "docker.sock", "filesystem.write"
  riskLevel: 'critical' | 'high';
  explanation: string;       // Why this is dangerous
  mitigation?: string;       // How to use safely
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
  findings: Array<Finding | ContextualFinding>;  // ContextualFinding when context_enabled=true
  summary: ScanSummary;
  test_findings?: Array<Finding | ContextualFinding>;  // Separate channel - informational only, doesn't affect status
  context_enabled?: boolean;   // Whether context-aware scanning was used
}

export type ASTRecommendation = 'block' | 'flag' | 'review' | 'pass';

export interface ASTFinding extends Finding {
  confidence: number;              // 0.0-1.0
  recommendation: ASTRecommendation;
  ast_node_type: string;           // e.g. 'CallExpression'
  argument_type: string;           // e.g. 'Identifier'
}

export const AST_EXTENSIONS = ['js', 'ts', 'jsx', 'tsx'];

export interface ScanConfig {
  maxFiles?: number;
  maxFileSize?: number;
  skipDirs?: string[];
  severityThreshold?: Severity;
  patterns?: ThreatPattern[];
  fileExtensions?: string[];
  stopOnFirstCritical?: boolean;

  // Context-aware scanning (opt-in for now)
  enableContextAwareness?: boolean;  // default: false

  // Separate test findings (don't affect status)
  includeTestFindings?: boolean;     // default: false

  // Declared capabilities from permissions.json (trusted source)
  declaredCapabilities?: string[];   // e.g., ['filesystem.read', 'docker.sock']

  // AST-based analysis (opt-in)
  enableASTAnalysis?: boolean;       // default: false
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
