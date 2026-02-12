import type { AuditFinding, Dependency } from '../types.js';
import { DEFAULT_ADVISORY_TIMEOUT } from '../types.js';

export interface Advisory {
  id: number;
  module_name: string;
  severity: string;
  title: string;
  url: string;
  vulnerable_versions: string;
}

export async function checkNpmAdvisories(
  deps: Dependency[],
  timeout?: number,
): Promise<AuditFinding[]> {
  const npmDeps = deps.filter(d => d.source === 'package.json');
  if (npmDeps.length === 0) return [];

  const body: Record<string, string[]> = {};
  for (const dep of npmDeps) {
    body[dep.name] = [dep.version];
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout ?? DEFAULT_ADVISORY_TIMEOUT);

    const response = await fetch('https://registry.npmjs.org/-/npm/v1/security/advisories/bulk', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (!response.ok) {
      return [{
        id: 'advisory_unavailable',
        severity: 'medium',
        category: 'cve',
        message: `npm advisory API returned HTTP ${response.status} — CVE check skipped`,
      }];
    }

    const advisories = await response.json() as Record<string, Advisory[]>;
    const findings: AuditFinding[] = [];

    for (const [pkgName, advList] of Object.entries(advisories)) {
      for (const adv of advList) {
        const severity = mapSeverity(adv.severity);
        findings.push({
          id: 'npm_advisory',
          severity,
          category: 'cve',
          message: `${adv.title} (${adv.url})`,
          dependency: pkgName,
          cve: adv.url ?? `npm-advisory-${adv.id}`,
        });
      }
    }

    return findings;
  } catch {
    return [{
      id: 'advisory_unavailable',
      severity: 'medium',
      category: 'cve',
      message: 'npm advisory API unreachable — CVE check skipped',
    }];
  }
}

function mapSeverity(npmSeverity: string): 'critical' | 'high' | 'medium' | 'low' {
  switch (npmSeverity) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'moderate': return 'medium';
    default: return 'low';
  }
}
