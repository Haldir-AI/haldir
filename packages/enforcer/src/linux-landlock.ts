import type { PermissionsPolicy, SpawnPolicy } from './types.js';
import { getNodeSystemPaths } from './node-permissions.js';

export function buildLinuxLandlockArgs(
  policy: PermissionsPolicy,
  command: string,
  args: string[],
  env: Record<string, string>,
): SpawnPolicy {
  // Stable since Node 22.13. Node 24 rejects --experimental-permission in NODE_OPTIONS.
  const nodeArgs: string[] = ['--permission'];

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
    backend: 'linux-landlock',
    enforced: {
      filesystem: true,
      network: false,
      exec: true,
    },
  };
}
