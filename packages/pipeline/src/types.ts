import type { ScanResult, ScanConfig } from '@haldir/scanner';
import type { AuditResult, AuditConfig } from '@haldir/auditor';
import type { SandboxResult, SandboxConfig } from '@haldir/sandbox';
import type { ReviewResult, ReviewConfig } from '@haldir/reviewer';

export type PipelineStatus = 'approved' | 'rejected' | 'amber' | 'error';

export interface PipelineConfig {
  scanner?: ScanConfig;
  auditor?: AuditConfig;
  sandbox?: SandboxConfig;
  reviewer?: ReviewConfig;
  skipLayers?: number[];
  failFast?: boolean;
  /** Treat layer errors as rejections. Default: true (fail-closed). */
  treatErrorAsReject?: boolean;
}

export interface LayerResult {
  layer: number;
  name: string;
  status: 'pass' | 'fail' | 'flag' | 'skip' | 'error';
  duration_ms: number;
  error?: string;
}

export interface PipelineResult {
  status: PipelineStatus;
  duration_ms: number;
  layers: LayerResult[];
  scan?: ScanResult;
  audit?: AuditResult;
  sandbox?: SandboxResult;
  review?: ReviewResult;
  rejectedAt?: number;
  score?: number;
}
