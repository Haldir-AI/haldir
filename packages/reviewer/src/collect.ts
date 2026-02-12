import { readFile, readdir, stat } from 'node:fs/promises';
import { join, extname } from 'node:path';
import type { SkillContent } from './types.js';

const CODE_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.mts', '.cts',
  '.py', '.sh', '.bash',
  '.json', '.yaml', '.yml', '.toml',
  '.md',
]);

const SKIP_DIRS = new Set(['.vault', 'node_modules', '.git', '__pycache__', 'dist', '.venv', 'venv']);
const MAX_FILE_SIZE = 50_000;
const MAX_FILES = 30;

export async function collectSkillContent(skillDir: string): Promise<SkillContent> {
  let name = 'unknown';
  let version = '0.0.0';
  let description = '';

  try {
    const pkg = JSON.parse(await readFile(join(skillDir, 'package.json'), 'utf-8'));
    name = pkg.name ?? name;
    version = pkg.version ?? version;
    description = pkg.description ?? description;
  } catch { /* try SKILL.md */ }

  if (!description) {
    try {
      const skillMd = await readFile(join(skillDir, 'SKILL.md'), 'utf-8');
      const firstLine = skillMd.split('\n').find(l => l.trim().length > 0) ?? '';
      name = firstLine.replace(/^#+\s*/, '').trim() || name;
      description = skillMd.slice(0, 500);
    } catch { /* no SKILL.md */ }
  }

  let permissions: Record<string, unknown> | undefined;
  try {
    permissions = JSON.parse(
      await readFile(join(skillDir, '.vault', 'permissions.json'), 'utf-8')
    );
  } catch { /* no permissions */ }

  const files = await collectFiles(skillDir, '');

  return { name, version, description, files, permissions };
}

async function collectFiles(
  baseDir: string,
  relativePath: string,
  collected: { path: string; content: string }[] = [],
): Promise<{ path: string; content: string }[]> {
  if (collected.length >= MAX_FILES) return collected;

  const fullDir = join(baseDir, relativePath);
  let entries: string[];
  try {
    entries = await readdir(fullDir);
  } catch {
    return collected;
  }

  for (const entry of entries) {
    if (collected.length >= MAX_FILES) break;
    if (SKIP_DIRS.has(entry)) continue;

    const relPath = relativePath ? `${relativePath}/${entry}` : entry;
    const fullPath = join(baseDir, relPath);

    let entryStat;
    try {
      entryStat = await stat(fullPath);
    } catch {
      continue;
    }

    if (entryStat.isDirectory()) {
      await collectFiles(baseDir, relPath, collected);
    } else if (entryStat.isFile()) {
      const ext = extname(entry);
      if (CODE_EXTENSIONS.has(ext) || entry === 'SKILL.md' || entry === 'Dockerfile') {
        try {
          const content = await readFile(fullPath, 'utf-8');
          if (content.length <= MAX_FILE_SIZE) {
            collected.push({ path: relPath, content });
          }
        } catch { /* skip unreadable */ }
      }
    }
  }

  return collected;
}
