import { readFile, lstat, readdir } from 'node:fs/promises';
import { join, relative, resolve, isAbsolute } from 'node:path';
import { createHash } from 'node:crypto';
import { hashData, safeHashCompare, parseHashString } from './crypto.js';
import { VAULT_DIR, MAX_FILES, MAX_FILE_SIZE, MAX_TOTAL_SIZE } from './types.js';
import type { IntegrityManifest, FilesystemCheckResult, VerifyError, WalkOptions } from './types.js';

function normalizePath(p: string): string {
  return p.split('\\').join('/');
}

async function walkDir(dir: string, rootDir: string, excludeVault: boolean): Promise<{ path: string; relativePath: string }[]> {
  const results: { path: string; relativePath: string }[] = [];
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    const rel = normalizePath(relative(rootDir, fullPath));
    if (excludeVault && (rel.startsWith(VAULT_DIR + '/') || rel === VAULT_DIR)) continue;
    if (entry.isDirectory()) {
      const sub = await walkDir(fullPath, rootDir, excludeVault);
      results.push(...sub);
    } else {
      results.push({ path: fullPath, relativePath: rel });
    }
  }
  return results;
}

export async function hashFile(filePath: string): Promise<string> {
  const data = await readFile(filePath);
  return hashData(data);
}

export async function hashDirectory(dirPath: string): Promise<Record<string, string>> {
  const files = await walkDir(dirPath, dirPath, true);
  files.sort((a, b) => {
    const aBuf = Buffer.from(a.relativePath, 'utf-8');
    const bBuf = Buffer.from(b.relativePath, 'utf-8');
    return Buffer.compare(aBuf, bBuf);
  });
  const result: Record<string, string> = {};
  for (const f of files) {
    result[f.relativePath] = await hashFile(f.path);
  }
  return result;
}

export async function generateIntegrity(skillDir: string): Promise<IntegrityManifest> {
  const files = await hashDirectory(skillDir);
  return {
    schema_version: '1.0',
    algorithm: 'sha256',
    files,
    generated_at: new Date().toISOString(),
  };
}

export async function verifyIntegrity(
  skillDir: string,
  manifest: IntegrityManifest
): Promise<{ valid: boolean; mismatches: string[]; extraFiles: string[] }> {
  const mismatches: string[] = [];
  const extraFiles: string[] = [];

  for (const [filePath, expectedHash] of Object.entries(manifest.files)) {
    const resolved = resolve(skillDir, filePath);
    const normalizedRoot = resolve(skillDir);
    const rel = relative(normalizedRoot, resolved);
    if (rel.length === 0 || rel.startsWith('..') || isAbsolute(rel)) {
      mismatches.push(filePath);
      continue;
    }
    const fullPath = join(skillDir, filePath);
    try {
      const data = await readFile(fullPath);
      const actualHash = hashData(data);
      const expected = parseHashString(expectedHash);
      const actual = parseHashString(actualHash);
      const expectedBuf = Buffer.from(expected.hex, 'hex');
      const actualBuf = Buffer.from(actual.hex, 'hex');
      if (!safeHashCompare(expectedBuf, actualBuf)) {
        mismatches.push(filePath);
      }
    } catch {
      mismatches.push(filePath);
    }
  }

  const allFiles = await walkDir(skillDir, skillDir, true);
  for (const f of allFiles) {
    if (!(f.relativePath in manifest.files)) {
      extraFiles.push(f.relativePath);
    }
  }

  return {
    valid: mismatches.length === 0 && extraFiles.length === 0,
    mismatches,
    extraFiles,
  };
}

export async function checkFilesystem(
  dirPath: string,
  opts?: WalkOptions
): Promise<FilesystemCheckResult> {
  const errors: VerifyError[] = [];
  let fileCount = 0;
  let totalSize = 0;

  async function walk(dir: string) {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      const stats = await lstat(fullPath);

      if (stats.isSymbolicLink()) {
        errors.push({
          code: 'E_SYMLINK',
          message: `Symlink detected: ${normalizePath(relative(dirPath, fullPath))}`,
          file: normalizePath(relative(dirPath, fullPath)),
        });
        continue;
      }

      if (stats.isDirectory()) {
        await walk(fullPath);
        continue;
      }

      if (stats.isFile()) {
        if (!opts?.skipHardlinkCheck && stats.nlink > 1) {
          errors.push({
            code: 'E_HARDLINK',
            message: `Hard link detected: ${normalizePath(relative(dirPath, fullPath))}`,
            file: normalizePath(relative(dirPath, fullPath)),
          });
        }

        fileCount++;
        totalSize += stats.size;

        if (fileCount > MAX_FILES) {
          errors.push({
            code: 'E_LIMITS',
            message: `File count ${fileCount} exceeds limit ${MAX_FILES}`,
          });
          return;
        }

        if (stats.size > MAX_FILE_SIZE) {
          errors.push({
            code: 'E_LIMITS',
            message: `File ${normalizePath(relative(dirPath, fullPath))} exceeds size limit`,
            file: normalizePath(relative(dirPath, fullPath)),
          });
        }

        if (totalSize > MAX_TOTAL_SIZE) {
          errors.push({
            code: 'E_LIMITS',
            message: `Total size ${totalSize} exceeds limit ${MAX_TOTAL_SIZE}`,
          });
          return;
        }
      }
    }
  }

  await walk(dirPath);

  return {
    valid: errors.length === 0,
    errors,
    fileCount,
    totalSize,
  };
}
