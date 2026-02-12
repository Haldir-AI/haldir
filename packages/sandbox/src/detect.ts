import { readFile, readdir, access } from 'node:fs/promises';
import { join } from 'node:path';

export type SkillRuntime = 'node' | 'python' | 'shell' | 'unknown';

export interface DetectedEntrypoint {
  runtime: SkillRuntime;
  command: string;
  args: string[];
}

export async function detectEntrypoint(skillDir: string): Promise<DetectedEntrypoint> {
  const files = await readdir(skillDir).catch(() => [] as string[]);

  const pkgJsonPath = join(skillDir, 'package.json');
  try {
    const content = await readFile(pkgJsonPath, 'utf-8');
    const pkg = JSON.parse(content);
    if (pkg.scripts?.start) {
      return { runtime: 'node', command: 'npm', args: ['start'] };
    }
    if (pkg.main) {
      return { runtime: 'node', command: 'node', args: [pkg.main] };
    }
  } catch { /* no package.json */ }

  if (files.includes('main.py')) {
    return { runtime: 'python', command: 'python3', args: ['main.py'] };
  }
  if (files.includes('app.py')) {
    return { runtime: 'python', command: 'python3', args: ['app.py'] };
  }
  if (files.includes('index.py')) {
    return { runtime: 'python', command: 'python3', args: ['index.py'] };
  }

  if (files.includes('index.js')) {
    return { runtime: 'node', command: 'node', args: ['index.js'] };
  }
  if (files.includes('index.mjs')) {
    return { runtime: 'node', command: 'node', args: ['index.mjs'] };
  }
  if (files.includes('main.js')) {
    return { runtime: 'node', command: 'node', args: ['main.js'] };
  }

  if (files.includes('run.sh')) {
    return { runtime: 'shell', command: 'sh', args: ['run.sh'] };
  }

  return { runtime: 'unknown', command: 'echo', args: ['no entrypoint found'] };
}

export async function hasNodeModules(skillDir: string): Promise<boolean> {
  try {
    await access(join(skillDir, 'node_modules'));
    return true;
  } catch {
    return false;
  }
}
