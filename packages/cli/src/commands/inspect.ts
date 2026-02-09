import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

export async function inspectCommand(dir: string): Promise<void> {
  const vaultDir = join(dir, '.vault');

  const files = ['attestation.json', 'permissions.json', 'integrity.json'];
  for (const f of files) {
    try {
      const raw = await readFile(join(vaultDir, f), 'utf-8');
      const parsed = JSON.parse(raw);
      console.log(`--- ${f} ---`);
      console.log(JSON.stringify(parsed, null, 2));
      console.log();
    } catch {
      console.error(`Could not read ${f}`);
    }
  }
}
