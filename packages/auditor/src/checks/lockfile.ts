import type { AuditFinding, ManifestType } from '../types.js';

export function checkLockfile(manifests: ManifestType[], fileList: string[]): AuditFinding[] {
  const findings: AuditFinding[] = [];

  if (manifests.includes('package.json')) {
    const hasLock = fileList.some(f =>
      f === 'package-lock.json' ||
      f === 'pnpm-lock.yaml' ||
      f === 'yarn.lock' ||
      f === 'bun.lockb'
    );
    if (!hasLock) {
      findings.push({
        id: 'no_lockfile_node',
        severity: 'high',
        category: 'no_lockfile',
        message: 'No lock file found for Node.js project (package-lock.json, pnpm-lock.yaml, yarn.lock, or bun.lockb)',
        file: 'package.json',
      });
    }
  }

  if (manifests.includes('pyproject.toml') || manifests.includes('requirements.txt')) {
    const hasPythonLock = fileList.some(f =>
      f === 'requirements.txt' ||
      f === 'poetry.lock' ||
      f === 'pdm.lock' ||
      f === 'uv.lock'
    );
    if (!hasPythonLock && !manifests.includes('requirements.txt')) {
      findings.push({
        id: 'no_lockfile_python',
        severity: 'medium',
        category: 'no_lockfile',
        message: 'No lock file found for Python project (requirements.txt, poetry.lock, pdm.lock, or uv.lock)',
        file: 'pyproject.toml',
      });
    }
  }

  return findings;
}
