import type { AuditFinding, Dependency } from '../types.js';

const KNOWN_TYPOSQUATS = [
  { legit: 'lodash', typos: ['lodash-utils', 'lodashs', 'lodash.'] },
  { legit: 'express', typos: ['expres', 'expresss'] },
  { legit: 'requests', typos: ['request-', 'requets'] },
  { legit: 'colorama', typos: ['colorsama', 'coloarama'] },
];

const INSTALL_HOOK_NAMES = ['preinstall', 'postinstall', 'preuninstall', 'install'];

export function checkSuspiciousPackages(deps: Dependency[]): AuditFinding[] {
  const findings: AuditFinding[] = [];

  for (const dep of deps) {
    if (dep.name.startsWith('@') && dep.name.split('/').length === 2) {
      const [scope, pkg] = dep.name.split('/');
      if (scope.length <= 2) {
        findings.push({
          id: 'suspicious_scope',
          severity: 'medium',
          category: 'suspicious',
          message: `Suspiciously short scope in ${dep.name} — possible typosquat`,
          dependency: dep.name,
        });
      }
    }

    if (dep.version === '*' || dep.version === 'latest') {
      findings.push({
        id: 'wildcard_version',
        severity: 'high',
        category: 'unpinned',
        message: `Wildcard version "${dep.version}" for ${dep.name} — installs any version`,
        dependency: dep.name,
      });
    }

    if (dep.version.startsWith('git+') || dep.version.startsWith('github:') || dep.version.startsWith('http')) {
      findings.push({
        id: 'git_dependency',
        severity: 'high',
        category: 'suspicious',
        message: `Git/URL dependency for ${dep.name}: ${dep.version} — bypasses registry`,
        dependency: dep.name,
      });
    }
  }

  return findings;
}

export function checkInstallScripts(packageJsonContent: string): AuditFinding[] {
  const findings: AuditFinding[] = [];

  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(packageJsonContent);
  } catch {
    return [];
  }

  const scripts = pkg.scripts as Record<string, string> | undefined;
  if (!scripts) return [];

  for (const hook of INSTALL_HOOK_NAMES) {
    if (scripts[hook]) {
      findings.push({
        id: 'install_script',
        severity: 'high',
        category: 'suspicious',
        message: `Install hook "${hook}" found: ${scripts[hook]}`,
        file: 'package.json',
      });
    }
  }

  return findings;
}
