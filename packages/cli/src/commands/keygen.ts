import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { generateKeyPair } from '@haldir/core';

export async function keygenCommand(opts: { output?: string } = {}): Promise<void> {
  const kp = generateKeyPair();
  const outputDir = opts.output || '.';

  const keyPath = join(outputDir, 'haldir.key');
  const pubPath = join(outputDir, 'haldir.pub');
  const keyIdPath = join(outputDir, 'haldir.keyid');

  await writeFile(keyPath, kp.privateKey, { mode: 0o600 });
  await writeFile(pubPath, kp.publicKey);
  await writeFile(keyIdPath, kp.keyId);

  console.log(`Key ID: ${kp.keyId}`);
  console.log(`Private key: ${keyPath}`);
  console.log(`Public key:  ${pubPath}`);
}
