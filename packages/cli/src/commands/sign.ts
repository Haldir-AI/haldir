import { readFile } from 'node:fs/promises';
import { createEnvelope, createKeylessEnvelope, deriveKeyId } from '@haldir/core';

interface SignOptions {
  key?: string;
  keyless?: boolean;
  identityToken?: string;
  name?: string;
  skillVersion?: string;
  type?: string;
}

export async function signCommand(dir: string, opts: SignOptions): Promise<void> {
  const skill = {
    name: opts.name ?? 'unnamed',
    version: opts.skillVersion ?? '0.0.0',
    type: opts.type ?? 'skill.md',
  };

  if (opts.keyless) {
    await createKeylessEnvelope(dir, {
      skill,
      identityToken: opts.identityToken,
    });

    console.log(`✓ Signed (keyless/Sigstore): ${dir}`);
    console.log(`Signature recorded in Rekor transparency log`);
    return;
  }

  if (!opts.key) {
    console.error('Error: --key <path> is required (or use --keyless for Sigstore signing)');
    process.exit(2);
  }

  const privateKey = await readFile(opts.key, 'utf-8');
  const keyId = deriveKeyId(privateKey);

  await createEnvelope(dir, privateKey, {
    keyId,
    skill,
  });

  console.log(`✓ Signed: ${dir}`);
  console.log(`Key ID: ${keyId}`);
}
