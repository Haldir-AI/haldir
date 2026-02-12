import { readFile, readdir, stat, lstat, realpath } from 'node:fs/promises';
import { join, relative, extname } from 'node:path';
import { DEFAULT_SKIP_DIRS, DEFAULT_MAX_FILES, DEFAULT_MAX_FILE_SIZE } from './types.js';

export interface FileEntry {
  absolutePath: string;
  relativePath: string;
  extension: string;
  sizeBytes: number;
}

export interface WalkResult {
  files: FileEntry[];
  skippedCount: number;
}

export function getExtension(filePath: string): string {
  const ext = extname(filePath).toLowerCase();
  return ext.startsWith('.') ? ext.slice(1) : ext;
}

export function isBinaryBuffer(buf: Buffer): boolean {
  const checkLength = Math.min(buf.length, 512);
  for (let i = 0; i < checkLength; i++) {
    if (buf[i] === 0) return true;
  }
  return false;
}

export async function walkDirectory(
  rootDir: string,
  skipDirs: string[] = DEFAULT_SKIP_DIRS,
  maxFiles: number = DEFAULT_MAX_FILES,
  maxFileSize: number = DEFAULT_MAX_FILE_SIZE
): Promise<WalkResult> {
  const files: FileEntry[] = [];
  let skippedCount = 0;
  const skipSet = new Set(skipDirs);
  const resolvedRoot = await realpath(rootDir);

  async function walk(dir: string): Promise<void> {
    if (files.length >= maxFiles) return;

    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (files.length >= maxFiles) return;

      const fullPath = join(dir, entry.name);

      if (entry.isDirectory()) {
        if (skipSet.has(entry.name)) {
          skippedCount++;
          continue;
        }
        try {
          const realDirPath = await realpath(fullPath);
          if (!realDirPath.startsWith(resolvedRoot + '/') && realDirPath !== resolvedRoot) {
            skippedCount++;
            continue;
          }
        } catch {
          skippedCount++;
          continue;
        }
        await walk(fullPath);
      } else if (entry.isFile()) {
        try {
          const realFilePath = await realpath(fullPath);
          if (!realFilePath.startsWith(resolvedRoot + '/')) {
            skippedCount++;
            continue;
          }
        } catch {
          skippedCount++;
          continue;
        }

        const st = await lstat(fullPath);
        if (st.size > maxFileSize) {
          skippedCount++;
          continue;
        }

        const relPath = relative(rootDir, fullPath).replace(/\\/g, '/');
        files.push({
          absolutePath: fullPath,
          relativePath: relPath,
          extension: getExtension(fullPath),
          sizeBytes: st.size,
        });
      }
    }
  }

  await walk(rootDir);
  return { files, skippedCount };
}

export async function readFileLines(
  filePath: string
): Promise<string[] | null> {
  const buf = await readFile(filePath);
  if (isBinaryBuffer(buf)) return null;
  return buf.toString('utf-8').split('\n');
}
