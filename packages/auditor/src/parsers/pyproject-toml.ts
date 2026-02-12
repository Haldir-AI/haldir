import type { Dependency } from '../types.js';

const PINNED_RE = /^==\d+/;

export function parsePyprojectToml(content: string): Dependency[] {
  const deps: Dependency[] = [];

  const depsSection = extractTomlArray(content, 'dependencies');
  for (const spec of depsSection) {
    const parsed = parsePythonDep(spec);
    if (parsed) deps.push(parsed);
  }

  const optionalDeps = extractTomlSection(content, 'optional-dependencies');
  for (const spec of optionalDeps) {
    const parsed = parsePythonDep(spec);
    if (parsed) deps.push(parsed);
  }

  const scriptDeps = extractPep723(content);
  for (const spec of scriptDeps) {
    const parsed = parsePythonDep(spec);
    if (parsed) deps.push(parsed);
  }

  return deps;
}

function parsePythonDep(spec: string): Dependency | null {
  const cleaned = spec.trim().replace(/["']/g, '');
  if (!cleaned) return null;

  const match = cleaned.match(/^([a-zA-Z0-9_.-]+)\s*([><=!~]+\s*\S+(?:\s*,\s*[><=!~]+\s*\S+)*)?/);
  if (!match) return null;

  const name = match[1];
  const versionSpec = (match[2] ?? '').trim();
  const pinned = versionSpec.startsWith('==') && /^==\d+\.\d+/.test(versionSpec);

  return {
    name,
    version: versionSpec || '*',
    pinned,
    hasHash: false,
    source: 'pyproject.toml',
  };
}

function extractTomlArray(content: string, key: string): string[] {
  const regex = new RegExp(`^${key}\\s*=\\s*\\[([^\\]]*(?:\\n[^\\]]*)*?)\\]`, 'm');
  const match = content.match(regex);
  if (!match) return [];

  return match[1]
    .split(/,|\n/)
    .map(s => s.trim().replace(/^["']|["']$/g, ''))
    .filter(s => s.length > 0 && !s.startsWith('#'));
}

function extractTomlSection(content: string, section: string): string[] {
  const sectionRegex = new RegExp(`\\[(?:project\\.)?${section.replace('.', '\\.')}\\]`);
  const sectionStart = content.search(sectionRegex);
  if (sectionStart === -1) return [];

  const afterSection = content.slice(sectionStart);
  const headerEnd = afterSection.indexOf('\n');
  if (headerEnd === -1) return [];

  const sectionBody = afterSection.slice(headerEnd + 1);
  const nextSectionIdx = sectionBody.search(/^\[/m);
  const block = nextSectionIdx === -1 ? sectionBody : sectionBody.slice(0, nextSectionIdx);

  const results: string[] = [];
  const arrayRegex = /\w+\s*=\s*\[([^\]]*)\]/g;
  let m;
  while ((m = arrayRegex.exec(block)) !== null) {
    const items = m[1].split(/,|\n/).map(s => s.trim().replace(/^["']|["']$/g, '')).filter(Boolean);
    results.push(...items);
  }

  return results;
}

export function extractPep723(content: string): string[] {
  const marker = /# *(?:script|inline) *(?:dependencies|requires)/i;
  if (!marker.test(content)) return [];

  const deps: string[] = [];
  const lines = content.split('\n');
  let inBlock = false;

  for (const line of lines) {
    if (marker.test(line)) {
      inBlock = true;
      continue;
    }
    if (inBlock) {
      const trimmed = line.replace(/^#\s*/, '').trim();
      if (trimmed.startsWith('[') || trimmed.startsWith('-')) continue;
      if (trimmed === '' || trimmed === '"""' || trimmed === "'''") {
        inBlock = false;
        continue;
      }
      if (/^[a-zA-Z0-9_.-]/.test(trimmed)) {
        deps.push(trimmed.replace(/["']/g, ''));
      }
    }
  }

  return deps;
}
