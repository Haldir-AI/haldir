import { writeFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import type { PermissionsPolicy, SpawnPolicy } from './types.js';

export function generateSandboxProfile(policy: PermissionsPolicy): string {
  const rules: string[] = [
    '(version 1)',
    '(deny default)',
    '',
    '; Allow process execution',
    '(allow process-exec*)',
    '(allow process-fork)',
    '',
    '; Allow sysctl for Node.js runtime',
    '(allow sysctl-read)',
    '',
    '; Allow mach lookups (IPC, needed for Node.js)',
    '(allow mach-lookup)',
    '(allow mach-register)',
    '',
    '; Allow signal handling',
    '(allow signal (target self))',
  ];

  rules.push('', '; Filesystem read');
  for (const readPath of policy.filesystem.read) {
    rules.push(`(allow file-read* (subpath "${escapeSbPath(readPath)}"))`);
  }
  rules.push(
    '(allow file-read* (subpath "/usr/lib"))',
    '(allow file-read* (subpath "/usr/local"))',
    '(allow file-read* (subpath "/System"))',
    '(allow file-read* (subpath "/Library"))',
    '(allow file-read* (subpath "/private/var/db"))',
    `(allow file-read* (subpath "${escapeSbPath(tmpdir())}"))`,
    '(allow file-read-metadata)',
  );

  if (policy.filesystem.write.length > 0) {
    rules.push('', '; Filesystem write');
    for (const writePath of policy.filesystem.write) {
      rules.push(`(allow file-write* (subpath "${escapeSbPath(writePath)}"))`);
    }
  }
  rules.push(`(allow file-write* (subpath "${escapeSbPath(tmpdir())}"))`);

  rules.push('', '; Network');
  if (policy.network.type === 'all') {
    rules.push('(allow network*)');
  } else if (policy.network.type === 'allowlist') {
    rules.push('(allow network-outbound (remote tcp))');
    rules.push('(allow network-bind (local tcp))');
    rules.push('(allow system-socket)');
  } else {
    rules.push('; Network denied (no rules added)');
  }

  if (policy.exec) {
    rules.push('', '; Subprocess execution allowed');
    rules.push('(allow process-exec*)');
  }

  rules.push('');
  return rules.join('\n');
}

export async function buildDarwinSandboxArgs(
  policy: PermissionsPolicy,
  command: string,
  args: string[],
  env: Record<string, string>,
): Promise<SpawnPolicy & { profilePath: string }> {
  const profile = generateSandboxProfile(policy);
  const profilePath = join(tmpdir(), `haldir-sb-${randomBytes(8).toString('hex')}.sb`);
  await writeFile(profilePath, profile);

  return {
    command: '/usr/bin/sandbox-exec',
    args: ['-f', profilePath, command, ...args],
    env,
    backend: 'darwin-sandbox',
    profilePath,
    enforced: {
      filesystem: true,
      network: true,
      exec: !policy.exec,
    },
  };
}

export async function cleanupProfile(profilePath: string): Promise<void> {
  try { await unlink(profilePath); } catch { /* ignore */ }
}

function escapeSbPath(p: string): string {
  return p.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}
