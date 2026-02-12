import type { AuditFinding } from '../types.js';
import { extractPep723 } from '../parsers/pyproject-toml.js';

export function checkPep723Scripts(fileContents: Map<string, string>): AuditFinding[] {
  const findings: AuditFinding[] = [];

  for (const [filePath, content] of fileContents) {
    if (!filePath.endsWith('.py')) continue;

    const inlineDeps = extractPep723(content);
    if (inlineDeps.length === 0) continue;

    findings.push({
      id: 'pep723_inline_deps',
      severity: 'high',
      category: 'pep723',
      message: `PEP 723 inline dependencies in ${filePath}: ${inlineDeps.join(', ')} — deferred dependency attack vector`,
      file: filePath,
    });

    for (const dep of inlineDeps) {
      const hasPinned = /==\d+/.test(dep);
      if (!hasPinned) {
        findings.push({
          id: 'pep723_unpinned',
          severity: 'critical',
          category: 'pep723',
          message: `Unpinned PEP 723 dependency "${dep}" in ${filePath} — arbitrary version resolution at runtime`,
          dependency: dep.replace(/[><=!~].*/,'').trim(),
          file: filePath,
        });
      }
    }
  }

  return findings;
}
