import { readFile } from 'node:fs/promises';
import { appendSignature, deriveKeyId } from '@haldir/core';

interface CosignOptions {
  key: string;
  trustedKey: string[];
}

export async function cosignCommand(dir: string, opts: CosignOptions): Promise<void> {
  const privateKey = await readFile(opts.key, 'utf-8');
  const keyId = deriveKeyId(privateKey);

  if (!opts.trustedKey || opts.trustedKey.length === 0) {
    console.error('Error: --trusted-key <path> is required (at least one trusted public key to verify existing signatures)');
    process.exit(2);
  }

  const trustedKeys: Record<string, string> = {};
  for (const keyPath of opts.trustedKey) {
    const pubKey = await readFile(keyPath, 'utf-8');
    const kid = deriveKeyId(pubKey);
    trustedKeys[kid] = pubKey;
  }

  await appendSignature(dir, privateKey, undefined, trustedKeys);

  console.log(`✓ Co-signed: ${dir}`);
  console.log(`Key ID: ${keyId}`);
}
