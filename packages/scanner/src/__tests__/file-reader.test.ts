import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { getExtension, isBinaryBuffer, walkDirectory, readFileLines } from '../file-reader.js';

describe('getExtension', () => {
  it('returns extension without dot', () => {
    expect(getExtension('file.py')).toBe('py');
  });

  it('returns lowercase', () => {
    expect(getExtension('FILE.JS')).toBe('js');
  });

  it('returns last extension for double-dotted files', () => {
    expect(getExtension('file.test.ts')).toBe('ts');
  });

  it('returns empty for no extension', () => {
    expect(getExtension('Makefile')).toBe('');
  });
});

describe('isBinaryBuffer', () => {
  it('detects NUL bytes as binary', () => {
    const buf = Buffer.from([0x48, 0x65, 0x6c, 0x00, 0x6f]);
    expect(isBinaryBuffer(buf)).toBe(true);
  });

  it('text content is not binary', () => {
    const buf = Buffer.from('Hello, world!\n');
    expect(isBinaryBuffer(buf)).toBe(false);
  });

  it('PNG header is binary', () => {
    const buf = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00]);
    expect(isBinaryBuffer(buf)).toBe(true);
  });

  it('empty buffer is not binary', () => {
    expect(isBinaryBuffer(Buffer.alloc(0))).toBe(false);
  });
});

describe('walkDirectory', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'haldir-scan-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('finds files recursively', async () => {
    await writeFile(join(tempDir, 'file.py'), 'print("hi")');
    await mkdir(join(tempDir, 'sub'));
    await writeFile(join(tempDir, 'sub', 'file.js'), 'console.log("hi")');

    const result = await walkDirectory(tempDir);
    expect(result.files).toHaveLength(2);
    expect(result.files.map(f => f.relativePath).sort()).toEqual(['file.py', 'sub/file.js']);
  });

  it('skips configured directories', async () => {
    await mkdir(join(tempDir, 'node_modules'));
    await writeFile(join(tempDir, 'node_modules', 'dep.js'), 'module.exports = {}');
    await writeFile(join(tempDir, 'app.js'), 'const x = 1;');

    const result = await walkDirectory(tempDir);
    expect(result.files).toHaveLength(1);
    expect(result.files[0].relativePath).toBe('app.js');
    expect(result.skippedCount).toBe(1);
  });

  it('respects maxFiles limit', async () => {
    for (let i = 0; i < 5; i++) {
      await writeFile(join(tempDir, `file${i}.txt`), 'content');
    }

    const result = await walkDirectory(tempDir, [], 3);
    expect(result.files.length).toBeLessThanOrEqual(3);
  });

  it('skips files exceeding maxFileSize', async () => {
    await writeFile(join(tempDir, 'small.txt'), 'small');
    await writeFile(join(tempDir, 'big.txt'), 'x'.repeat(1000));

    const result = await walkDirectory(tempDir, [], 10000, 100);
    expect(result.files).toHaveLength(1);
    expect(result.files[0].relativePath).toBe('small.txt');
    expect(result.skippedCount).toBe(1);
  });

  it('normalizes paths to forward slashes', async () => {
    await mkdir(join(tempDir, 'sub'));
    await writeFile(join(tempDir, 'sub', 'file.py'), 'pass');

    const result = await walkDirectory(tempDir);
    expect(result.files[0].relativePath).toBe('sub/file.py');
  });
});

describe('readFileLines', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'haldir-read-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('reads text file into lines', async () => {
    const path = join(tempDir, 'test.py');
    await writeFile(path, 'line1\nline2\nline3');

    const lines = await readFileLines(path);
    expect(lines).toEqual(['line1', 'line2', 'line3']);
  });

  it('returns null for binary files', async () => {
    const path = join(tempDir, 'test.bin');
    await writeFile(path, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00]));

    const lines = await readFileLines(path);
    expect(lines).toBeNull();
  });
});
