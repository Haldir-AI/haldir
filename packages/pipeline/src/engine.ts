import { scanDirectory } from '@haldir/scanner';
import type { ScanResult } from '@haldir/scanner';
import { auditDirectory } from '@haldir/auditor';
import type { AuditResult } from '@haldir/auditor';
import { sandboxSkill } from '@haldir/sandbox';
import type { SandboxResult } from '@haldir/sandbox';
import { reviewSkill, collectSkillContent } from '@haldir/reviewer';
import type { ReviewResult } from '@haldir/reviewer';
import type { PipelineConfig, PipelineResult, LayerResult } from './types.js';

const LAYER_NAMES = ['static_analysis', 'dependency_audit', 'sandbox_execution', 'llm_audit'] as const;

export async function vetSkill(
  skillDir: string,
  config?: PipelineConfig,
): Promise<PipelineResult> {
  const start = performance.now();
  const layers: LayerResult[] = [];
  const skipLayers = new Set(config?.skipLayers ?? []);
  const failFast = config?.failFast ?? true;

  let rejected = false;
  let rejectedAt: number | undefined;
  let scan: ScanResult | undefined;
  let audit: AuditResult | undefined;
  let sandbox: SandboxResult | undefined;
  let review: ReviewResult | undefined;

  // Layer 1: Static Analysis
  if (!skipLayers.has(1)) {
    const t = performance.now();
    try {
      scan = await scanDirectory(skillDir, config?.scanner);
      const s = mapStatus(scan.status);
      layers.push({ layer: 1, name: LAYER_NAMES[0], status: s, duration_ms: elapsed(t) });
      if (scan.status === 'reject') { rejected = true; rejectedAt = 1; }
    } catch (err) {
      layers.push({ layer: 1, name: LAYER_NAMES[0], status: 'error', duration_ms: elapsed(t), error: String(err) });
    }
  } else {
    layers.push({ layer: 1, name: LAYER_NAMES[0], status: 'skip', duration_ms: 0 });
  }

  if (rejected && failFast) return finalize(start, layers, rejectedAt, { scan, audit, sandbox, review });

  // Layer 2: Dependency Audit
  if (!skipLayers.has(2)) {
    const t = performance.now();
    try {
      audit = await auditDirectory(skillDir, config?.auditor);
      const s = mapStatus(audit.status);
      layers.push({ layer: 2, name: LAYER_NAMES[1], status: s, duration_ms: elapsed(t) });
      if (audit.status === 'reject' && !rejected) { rejected = true; rejectedAt = 2; }
    } catch (err) {
      layers.push({ layer: 2, name: LAYER_NAMES[1], status: 'error', duration_ms: elapsed(t), error: String(err) });
    }
  } else {
    layers.push({ layer: 2, name: LAYER_NAMES[1], status: 'skip', duration_ms: 0 });
  }

  if (rejected && failFast) return finalize(start, layers, rejectedAt, { scan, audit, sandbox, review });

  // Layer 3: Sandbox Execution
  if (!skipLayers.has(3)) {
    const t = performance.now();
    try {
      sandbox = await sandboxSkill(skillDir, config?.sandbox);
      const s = mapStatus(sandbox.status);
      layers.push({ layer: 3, name: LAYER_NAMES[2], status: s, duration_ms: elapsed(t) });
      if (sandbox.status === 'reject' && !rejected) { rejected = true; rejectedAt = 3; }
    } catch (err) {
      layers.push({ layer: 3, name: LAYER_NAMES[2], status: 'error', duration_ms: elapsed(t), error: String(err) });
    }
  } else {
    layers.push({ layer: 3, name: LAYER_NAMES[2], status: 'skip', duration_ms: 0 });
  }

  if (rejected && failFast) return finalize(start, layers, rejectedAt, { scan, audit, sandbox, review });

  // Layer 4: LLM Semantic Audit
  if (!skipLayers.has(4) && config?.reviewer) {
    const t = performance.now();
    try {
      const skill = await collectSkillContent(skillDir);
      review = await reviewSkill(skill, config.reviewer);
      const s = review.status === 'reject' ? 'fail' : review.status === 'amber' ? 'flag' : 'pass';
      layers.push({ layer: 4, name: LAYER_NAMES[3], status: s, duration_ms: elapsed(t) });
      if (review.status === 'reject' && !rejected) { rejected = true; rejectedAt = 4; }
    } catch (err) {
      layers.push({ layer: 4, name: LAYER_NAMES[3], status: 'error', duration_ms: elapsed(t), error: String(err) });
    }
  } else {
    layers.push({ layer: 4, name: LAYER_NAMES[3], status: 'skip', duration_ms: 0 });
  }

  return finalize(start, layers, rejectedAt, { scan, audit, sandbox, review }, review?.score);
}

function mapStatus(s: string): 'pass' | 'fail' | 'flag' {
  return s === 'reject' ? 'fail' : s === 'flag' ? 'flag' : 'pass';
}

function elapsed(t: number): number {
  return Math.round(performance.now() - t);
}

function finalize(
  start: number,
  layers: LayerResult[],
  rejectedAt?: number,
  results?: { scan?: ScanResult; audit?: AuditResult; sandbox?: SandboxResult; review?: ReviewResult },
  score?: number,
): PipelineResult {
  const hasReject = layers.some(l => l.status === 'fail');
  const hasError = layers.some(l => l.status === 'error');
  const hasFlag = layers.some(l => l.status === 'flag');

  const status = hasReject ? 'rejected'
    : hasError ? 'error'
    : hasFlag ? 'amber'
    : 'approved';

  return {
    status,
    duration_ms: Math.round(performance.now() - start),
    layers,
    rejectedAt,
    score,
    scan: results?.scan,
    audit: results?.audit,
    sandbox: results?.sandbox,
    review: results?.review,
  };
}
