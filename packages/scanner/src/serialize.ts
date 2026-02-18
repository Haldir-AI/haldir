import { z } from 'zod';
import type { ThreatPattern, ThreatCategory, Severity } from './types.js';

export interface SerializedRegex {
  source: string;
  flags: string;
}

export interface SerializedThreatPattern {
  id: string;
  category: ThreatCategory;
  severity: Severity;
  name: string;
  description: string;
  regex: SerializedRegex;
  fileExtensions: string[];
}

export interface PatternBundle {
  version: string;
  releasedAt: string;
  patternCount: number;
  patterns: SerializedThreatPattern[];
}

const serializedRegexSchema = z.object({
  source: z.string(),
  flags: z.string(),
});

const categorySchema = z.enum([
  'exfiltration', 'privilege_escalation', 'supply_chain', 'prompt_injection',
  'persistence', 'campaign_indicator', 'credential_exposure', 'obfuscation',
]);

const severitySchema = z.enum(['critical', 'high', 'medium', 'low']);

const serializedPatternSchema = z.object({
  id: z.string(),
  category: categorySchema,
  severity: severitySchema,
  name: z.string(),
  description: z.string(),
  regex: serializedRegexSchema,
  fileExtensions: z.array(z.string()),
});

const patternBundleSchema = z.object({
  version: z.string(),
  releasedAt: z.string(),
  patternCount: z.number(),
  patterns: z.array(serializedPatternSchema),
});

export function serializePattern(p: ThreatPattern): SerializedThreatPattern {
  return {
    id: p.id,
    category: p.category,
    severity: p.severity,
    name: p.name,
    description: p.description,
    regex: { source: p.regex.source, flags: p.regex.flags },
    fileExtensions: p.fileExtensions,
  };
}

export function deserializePattern(s: SerializedThreatPattern): ThreatPattern {
  return {
    id: s.id,
    category: s.category,
    severity: s.severity,
    name: s.name,
    description: s.description,
    regex: new RegExp(s.regex.source, s.regex.flags),
    fileExtensions: s.fileExtensions,
  };
}

export function serializeBundle(
  version: string,
  patterns: readonly ThreatPattern[],
): PatternBundle {
  return {
    version,
    releasedAt: new Date().toISOString(),
    patternCount: patterns.length,
    patterns: patterns.map(serializePattern),
  };
}

export function validateBundle(data: unknown): PatternBundle {
  return patternBundleSchema.parse(data) as PatternBundle;
}

export function deserializeBundle(bundle: unknown): ThreatPattern[] {
  const validated = validateBundle(bundle);
  return validated.patterns.map(deserializePattern);
}
