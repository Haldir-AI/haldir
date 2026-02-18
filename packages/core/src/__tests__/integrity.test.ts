import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, mkdir, symlink, rm, link } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { hashFile, hashDirectory, checkFilesystem, generateIntegrity, verifyIntegrity } from '../integrity.js';

let tempDir: string;

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), 'haldir-test-'));
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

describe('hashFile', () => {
  it('returns sha256:<64hex> format', async () => {
    const f = join(tempDir, 'test.txt');
    await writeFile(f, 'hello');
    const hash = await hashFile(f);
    expect(hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('is deterministic', async () => {
    const f = join(tempDir, 'test.txt');
    await writeFile(f, 'hello');
    const h1 = await hashFile(f);
    const h2 = await hashFile(f);
    expect(h1).toBe(h2);
  });

  it('different content produces different hash', async () => {
    const f1 = join(tempDir, 'a.txt');
    const f2 = join(tempDir, 'b.txt');
    await writeFile(f1, 'hello');
    await writeFile(f2, 'world');
    const h1 = await hashFile(f1);
    const h2 = await hashFile(f2);
    expect(h1).not.toBe(h2);
  });

  it('LF vs CRLF produce different hashes', async () => {
    const f1 = join(tempDir, 'lf.txt');
    const f2 = join(tempDir, 'crlf.txt');
    await writeFile(f1, 'hello\nworld');
    await writeFile(f2, 'hello\r\nworld');
    const h1 = await hashFile(f1);
    const h2 = await hashFile(f2);
    expect(h1).not.toBe(h2);
  });
});

describe('hashDirectory', () => {
  it('uses forward-slash paths', async () => {
    await mkdir(join(tempDir, 'sub'));
    await writeFile(join(tempDir, 'sub', 'file.txt'), 'data');
    const result = await hashDirectory(tempDir);
    expect(Object.keys(result)).toContain('sub/file.txt');
  });

  it('normalizes nested paths to forward slashes (cross-platform)', async () => {
    await mkdir(join(tempDir, 'sub', 'deep'), { recursive: true });
    await writeFile(join(tempDir, 'sub', 'deep', 'file.txt'), 'data');
    const result = await hashDirectory(tempDir);
    const keys = Object.keys(result);
    expect(keys).toContain('sub/deep/file.txt');
    expect(keys.every(k => !k.includes('\\'))).toBe(true);
  });

  it('handles Unicode filenames in integrity manifest', async () => {
    await writeFile(join(tempDir, 'café.txt'), 'french');
    await writeFile(join(tempDir, '日本語.md'), 'japanese');
    const result = await hashDirectory(tempDir);
    expect(Object.keys(result)).toContain('café.txt');
    expect(Object.keys(result)).toContain('日本語.md');
  });

  it('sorts keys by UTF-8 byte order', async () => {
    await writeFile(join(tempDir, 'b.txt'), 'b');
    await writeFile(join(tempDir, 'a.txt'), 'a');
    const result = await hashDirectory(tempDir);
    const keys = Object.keys(result);
    expect(keys[0]).toBe('a.txt');
    expect(keys[1]).toBe('b.txt');
  });

  it('excludes .vault/ directory', async () => {
    await writeFile(join(tempDir, 'SKILL.md'), '# Test');
    await mkdir(join(tempDir, '.vault'));
    await writeFile(join(tempDir, '.vault', 'signature.json'), '{}');
    const result = await hashDirectory(tempDir);
    expect(Object.keys(result)).not.toContain('.vault/signature.json');
    expect(Object.keys(result)).toContain('SKILL.md');
  });

  it('includes dotfiles', async () => {
    await writeFile(join(tempDir, '.hidden'), 'secret');
    const result = await hashDirectory(tempDir);
    expect(Object.keys(result)).toContain('.hidden');
  });
});

describe('checkFilesystem', () => {
  it('passes for clean directory', async () => {
    await writeFile(join(tempDir, 'file.txt'), 'data');
    const result = await checkFilesystem(tempDir);
    expect(result.valid).toBe(true);
    expect(result.fileCount).toBe(1);
  });

  it('detects symlinks', async () => {
    await writeFile(join(tempDir, 'real.txt'), 'data');
    await symlink(join(tempDir, 'real.txt'), join(tempDir, 'link.txt'));
    const result = await checkFilesystem(tempDir);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.code === 'E_SYMLINK')).toBe(true);
  });

  it('detects hard links', async () => {
    const src = join(tempDir, 'original.txt');
    await writeFile(src, 'data');
    await link(src, join(tempDir, 'hardlink.txt'));
    const result = await checkFilesystem(tempDir);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.code === 'E_HARDLINK')).toBe(true);
  });

  it('skips hard link check when option set', async () => {
    const src = join(tempDir, 'original.txt');
    await writeFile(src, 'data');
    await link(src, join(tempDir, 'hardlink.txt'));
    const result = await checkFilesystem(tempDir, { skipHardlinkCheck: true });
    expect(result.errors.some((e) => e.code === 'E_HARDLINK')).toBe(false);
  });
});

describe('generateIntegrity + verifyIntegrity', () => {
  it('round-trips correctly', async () => {
    await writeFile(join(tempDir, 'SKILL.md'), '# Test Skill');
    const integrity = await generateIntegrity(tempDir);
    expect(integrity.algorithm).toBe('sha256');
    expect(integrity.files['SKILL.md']).toMatch(/^sha256:/);

    const result = await verifyIntegrity(tempDir, integrity);
    expect(result.valid).toBe(true);
    expect(result.mismatches).toHaveLength(0);
    expect(result.extraFiles).toHaveLength(0);
  });

  it('detects tampered files', async () => {
    await writeFile(join(tempDir, 'SKILL.md'), '# Original');
    const integrity = await generateIntegrity(tempDir);
    await writeFile(join(tempDir, 'SKILL.md'), '# Tampered');
    const result = await verifyIntegrity(tempDir, integrity);
    expect(result.valid).toBe(false);
    expect(result.mismatches).toContain('SKILL.md');
  });

  it('detects extra files', async () => {
    await writeFile(join(tempDir, 'SKILL.md'), '# Test');
    const integrity = await generateIntegrity(tempDir);
    await writeFile(join(tempDir, 'extra.txt'), 'surprise');
    const result = await verifyIntegrity(tempDir, integrity);
    expect(result.valid).toBe(false);
    expect(result.extraFiles).toContain('extra.txt');
  });
});
