import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type {
  AuditResult, AuditConfig, AuditFinding, AuditSummary,
  ManifestType, Dependency, SkillType,
} from './types.js';
import { SEVERITY_ORDER } from './types.js';
import { parsePackageJson, analyzePackageLockDepth, analyzePnpmLockDepth } from './parsers/package-json.js';
import { parseRequirementsTxt } from './parsers/requirements-txt.js';
import { parsePyprojectToml } from './parsers/pyproject-toml.js';
import {
  checkPinning, checkHashes, checkLockfile, checkDependencyCount,
  checkDepth, checkSuspiciousPackages, checkInstallScripts, checkPep723Scripts,
  checkNpmAdvisories,
} from './checks/index.js';
import type { PackageLockDepth } from './parsers/package-json.js';

const MANIFEST_FILES: Record<string, ManifestType> = {
  'package.json': 'package.json',
  'requirements.txt': 'requirements.txt',
  'pyproject.toml': 'pyproject.toml',
};

export async function auditDirectory(dirPath: string, config?: AuditConfig): Promise<AuditResult> {
  const start = performance.now();

  let fileList: string[];
  try {
    fileList = await readdir(dirPath);
  } catch {
    return emptyResult(start);
  }

  const manifests: ManifestType[] = [];
  const allDeps: Dependency[] = [];
  const fileContents = new Map<string, string>();
  let depthInfo: PackageLockDepth | null = null;
  let packageJsonRaw: string | null = null;

  for (const [filename, type] of Object.entries(MANIFEST_FILES)) {
    if (fileList.includes(filename)) {
      manifests.push(type);
      try {
        const content = await readFile(join(dirPath, filename), 'utf-8');
        fileContents.set(filename, content);

        if (type === 'package.json') {
          packageJsonRaw = content;
          allDeps.push(...parsePackageJson(content));
        } else if (type === 'requirements.txt') {
          allDeps.push(...parseRequirementsTxt(content));
        } else if (type === 'pyproject.toml') {
          allDeps.push(...parsePyprojectToml(content));
        }
      } catch { /* skip unreadable */ }
    }
  }

  if (fileList.includes('package-lock.json')) {
    try {
      const lockContent = await readFile(join(dirPath, 'package-lock.json'), 'utf-8');
      depthInfo = analyzePackageLockDepth(lockContent);
    } catch { /* skip */ }
  } else if (fileList.includes('pnpm-lock.yaml')) {
    try {
      const lockContent = await readFile(join(dirPath, 'pnpm-lock.yaml'), 'utf-8');
      depthInfo = analyzePnpmLockDepth(lockContent);
    } catch { /* skip */ }
  }

  const pyFiles = await collectPythonFiles(dirPath, fileList);
  for (const [path, content] of pyFiles) {
    fileContents.set(path, content);
  }

  const skillType = detectSkillType(fileList, config?.skillType);
  const findings: AuditFinding[] = [];

  findings.push(...checkPinning(allDeps));
  findings.push(...checkHashes(allDeps));
  findings.push(...checkLockfile(manifests, fileList));
  findings.push(...checkDependencyCount(allDeps, skillType, config?.maxDepsSkillMd, config?.maxDepsMcp));
  findings.push(...checkDepth(depthInfo, config?.maxDepthLevel));
  findings.push(...checkSuspiciousPackages(allDeps));
  findings.push(...checkPep723Scripts(fileContents));

  if (packageJsonRaw) {
    findings.push(...checkInstallScripts(packageJsonRaw));
  }

  if (config?.checkCves !== false && allDeps.some(d => d.source === 'package.json')) {
    const cveFfindings = await checkNpmAdvisories(allDeps, config?.advisoryTimeout);
    findings.push(...cveFfindings);
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const summary = computeSummary(findings);
  const status = summary.critical > 0 ? 'reject'
    : (summary.high > 0 || summary.medium > 0) ? 'flag'
    : 'pass';

  return {
    status,
    duration_ms: Math.round(performance.now() - start),
    manifests_found: manifests,
    dependencies_count: allDeps.length,
    lockfile_present: fileList.some(f =>
      ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lockb', 'poetry.lock', 'pdm.lock', 'uv.lock'].includes(f)
    ),
    findings,
    summary,
    dependencies: allDeps,
  };
}

function detectSkillType(fileList: string[], override?: SkillType): SkillType {
  if (override) return override;
  if (fileList.includes('SKILL.md') || fileList.includes('skill.md')) return 'skill.md';
  return 'mcp';
}

function computeSummary(findings: AuditFinding[]): AuditSummary {
  const summary = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) summary[f.severity]++;
  return summary;
}

function emptyResult(start: number): AuditResult {
  return {
    status: 'pass',
    duration_ms: Math.round(performance.now() - start),
    manifests_found: [],
    dependencies_count: 0,
    lockfile_present: false,
    findings: [],
    summary: { critical: 0, high: 0, medium: 0, low: 0 },
    dependencies: [],
  };
}

async function collectPythonFiles(dirPath: string, fileList: string[]): Promise<Map<string, string>> {
  const result = new Map<string, string>();
  for (const f of fileList) {
    if (f.endsWith('.py')) {
      try {
        const content = await readFile(join(dirPath, f), 'utf-8');
        result.set(f, content);
      } catch { /* skip */ }
    }
  }
  return result;
}
