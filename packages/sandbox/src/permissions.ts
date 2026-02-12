import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { PermissionsJson, SandboxConfig } from './types.js';

export async function loadPermissions(skillDir: string): Promise<PermissionsJson | null> {
  try {
    const content = await readFile(join(skillDir, '.vault', 'permissions.json'), 'utf-8');
    return JSON.parse(content) as PermissionsJson;
  } catch {
    return null;
  }
}

export function permissionsToSandboxConfig(
  perms: PermissionsJson | null,
  skillDir: string,
): Partial<SandboxConfig> {
  if (!perms) {
    return {
      allowNetwork: false,
      allowedReadPaths: [skillDir],
      allowedWritePaths: [],
    };
  }

  const readPaths = perms.filesystem?.read?.map(p =>
    p.startsWith('/') ? p : join(skillDir, p)
  ) ?? [skillDir];

  const writePaths = perms.filesystem?.write?.map(p =>
    p.startsWith('/') ? p : join(skillDir, p)
  ) ?? [];

  const allowNetwork = perms.network === true || (Array.isArray(perms.network) && perms.network.length > 0);

  return { allowNetwork, allowedReadPaths: readPaths, allowedWritePaths: writePaths };
}
