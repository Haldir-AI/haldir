import type { AuditFinding, Dependency } from '../types.js';

export function checkPinning(deps: Dependency[]): AuditFinding[] {
  const findings: AuditFinding[] = [];

  for (const dep of deps) {
    if (!dep.pinned) {
      findings.push({
        id: 'unpinned_dep',
        severity: 'high',
        category: 'unpinned',
        message: `Unpinned dependency: ${dep.name}@${dep.version} in ${dep.source}`,
        dependency: dep.name,
        file: dep.source,
      });
    }
  }

  return findings;
}

export function checkHashes(deps: Dependency[]): AuditFinding[] {
  const findings: AuditFinding[] = [];
  const reqDeps = deps.filter(d => d.source === 'requirements.txt');

  if (reqDeps.length === 0) return [];

  const hasAnyHash = reqDeps.some(d => d.hasHash);
  const allHaveHash = reqDeps.every(d => d.hasHash);

  if (hasAnyHash && !allHaveHash) {
    const unhashed = reqDeps.filter(d => !d.hasHash);
    for (const dep of unhashed) {
      findings.push({
        id: 'partial_hash',
        severity: 'medium',
        category: 'unpinned',
        message: `Dependency ${dep.name} missing --hash in requirements.txt (other deps have hashes)`,
        dependency: dep.name,
        file: 'requirements.txt',
      });
    }
  }

  return findings;
}
