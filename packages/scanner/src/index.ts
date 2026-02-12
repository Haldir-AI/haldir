export { scanDirectory } from './engine.js';
export { PATTERN_DB } from './patterns/index.js';
export type {
  ScanResult,
  ScanConfig,
  ScanSummary,
  Finding,
  ThreatPattern,
  ThreatCategory,
  Severity,
} from './types.js';
export {
  DEFAULT_SKIP_DIRS,
  DEFAULT_MAX_FILES,
  DEFAULT_MAX_FILE_SIZE,
  SEVERITY_ORDER,
  ALL_EXTENSIONS,
  CODE_EXTENSIONS,
  MARKDOWN_EXTENSIONS,
  CONFIG_EXTENSIONS,
} from './types.js';
