import { writeFile } from 'node:fs/promises';
import { generateKeyPair } from '@haldir/core';

export async function keygenCommand(): Promise<void> {
  const kp = generateKeyPair();
  await writeFile('haldir.key', kp.privateKey, { mode: 0o600 });
  await writeFile('haldir.pub', kp.publicKey);
  console.log(`Key ID: ${kp.keyId}`);
  console.log('Private key: haldir.key');
  console.log('Public key:  haldir.pub');
}
