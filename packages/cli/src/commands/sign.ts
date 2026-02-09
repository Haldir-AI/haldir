import { readFile } from 'node:fs/promises';
import { createEnvelope, deriveKeyId } from '@haldir/core';

interface SignOptions {
  key: string;
  name?: string;
  skillVersion?: string;
  type?: string;
}

export async function signCommand(dir: string, opts: SignOptions): Promise<void> {
  const privateKey = await readFile(opts.key, 'utf-8');
  const keyId = deriveKeyId(privateKey);

  await createEnvelope(dir, privateKey, {
    keyId,
    skill: {
      name: opts.name ?? 'unnamed',
      version: opts.skillVersion ?? '0.0.0',
      type: opts.type ?? 'skill.md',
    },
  });

  console.log(`Signed: ${dir}`);
  console.log(`Key ID: ${keyId}`);
}
