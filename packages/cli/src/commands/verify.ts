import { readFile } from 'node:fs/promises';
import { verifyEnvelope, deriveKeyId } from '@haldir/core';
import type { SignedRevocationList, VerifyOptions } from '@haldir/core';
import { toCliOutput } from '../utils/output.js';

interface VerifyCommandOptions {
  key: string;
  revocation?: string;
  context?: string;
  skipHardlinkCheck?: boolean;
}

export async function verifyCommand(dir: string, opts: VerifyCommandOptions): Promise<void> {
  const publicKey = await readFile(opts.key, 'utf-8');
  const keyId = deriveKeyId(publicKey);

  let revocationList: SignedRevocationList | undefined;
  if (opts.revocation) {
    const raw = await readFile(opts.revocation, 'utf-8');
    revocationList = JSON.parse(raw);
  }

  const context = (opts.context === 'runtime' ? 'runtime' : 'install') as VerifyOptions['context'];

  const result = await verifyEnvelope(dir, {
    trustedKeys: { [keyId]: publicKey },
    revocationList,
    context,
    skipHardlinkCheck: opts.skipHardlinkCheck,
  });

  const output = toCliOutput(result);
  console.log(JSON.stringify(output, null, 2));
  process.exit(result.valid ? 0 : 1);
}
