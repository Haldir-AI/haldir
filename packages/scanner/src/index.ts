export { scanDirectory } from './engine.js';
export { PATTERN_DB } from './patterns/index.js';
export { scanManifest } from './manifest.js';
export { analyzeFileAST } from './ast-analyzer.js';
export {
  serializePattern,
  deserializePattern,
  serializeBundle,
  deserializeBundle,
  validateBundle,
} from './serialize.js';
export type {
  SerializedThreatPattern,
  SerializedRegex,
  PatternBundle,
} from './serialize.js';
export type {
  ScanResult,
  ScanConfig,
  ScanSummary,
  Finding,
  ASTFinding,
  ASTRecommendation,
  ThreatPattern,
  ThreatCategory,
  Severity,
} from './types.js';
export {
  DEFAULT_SKIP_DIRS,
  DEFAULT_MAX_FILES,
  DEFAULT_MAX_FILE_SIZE,
  SEVERITY_ORDER,
  AST_EXTENSIONS,
  ALL_EXTENSIONS,
  CODE_EXTENSIONS,
  MARKDOWN_EXTENSIONS,
  CONFIG_EXTENSIONS,
} from './types.js';
