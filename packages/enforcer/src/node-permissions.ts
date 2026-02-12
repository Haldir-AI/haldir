import { dirname } from 'node:path';
import type { PermissionsPolicy, SpawnPolicy } from './types.js';

export function getNodeSystemPaths(): string[] {
  const paths: string[] = [];
  const nodeDir = dirname(dirname(process.execPath));
  paths.push(nodeDir);
  if (process.platform === 'darwin') {
    paths.push('/usr/lib/libSystem*', '/usr/local/lib/node_modules', '/etc/ssl/certs', '/private/var/folders');
  } else if (process.platform === 'linux') {
    paths.push('/usr/lib/x86_64-linux-gnu', '/usr/local/lib/node_modules', '/lib/x86_64-linux-gnu', '/etc/ssl/certs');
  }
  return paths;
}

export function buildNodePermissionArgs(
  policy: PermissionsPolicy,
  command: string,
  args: string[],
  env: Record<string, string>,
): SpawnPolicy {
  const nodeArgs: string[] = ['--experimental-permission'];

  const systemPaths = getNodeSystemPaths();
  const readPaths = [...new Set([...policy.filesystem.read, ...systemPaths])];
  for (const p of readPaths) {
    nodeArgs.push(`--allow-fs-read=${p}`);
  }

  for (const p of policy.filesystem.write) {
    nodeArgs.push(`--allow-fs-write=${p}`);
  }

  if (policy.exec) {
    nodeArgs.push('--allow-child-process');
  }

  const nodeOptions = nodeArgs.join(' ');
  const enforcedEnv = { ...env, NODE_OPTIONS: nodeOptions };

  return {
    command,
    args,
    env: enforcedEnv,
    backend: 'node-permissions',
    enforced: {
      filesystem: true,
      network: false,
      exec: true,
    },
  };
}
