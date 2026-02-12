import { readFile } from 'node:fs/promises';
import {
  verifyEnvelope,
  verifySigstoreEnvelope,
  hasSigstoreBundle,
  deriveKeyId,
} from '@haldir/core';
import type { SignedRevocationList, VerifyOptions, SigstoreVerifyOptions, TrustedIdentity } from '@haldir/core';
import { RevocationListSchema } from '@haldir/core';
import { toCliOutput } from '../utils/output.js';

interface VerifyCommandOptions {
  key?: string;
  keyless?: boolean;
  trustedIdentity?: string[];
  revocation?: string;
  revocationKey?: string;
  context?: string;
  skipHardlinkCheck?: boolean;
}

export async function verifyCommand(dir: string, opts: VerifyCommandOptions): Promise<void> {
  const context = (opts.context === 'runtime' ? 'runtime' : 'install') as VerifyOptions['context'];

  let revocationList: SignedRevocationList | undefined;
  if (opts.revocation) {
    const raw = await readFile(opts.revocation, 'utf-8');
    const parsed = JSON.parse(raw);
    const validated = RevocationListSchema.safeParse(parsed);
    if (!validated.success) {
      console.error(`Error: invalid revocation list: ${validated.error.message}`);
      process.exit(2);
    }
    revocationList = validated.data as SignedRevocationList;
  }

  // Auto-detect: use Sigstore path if --keyless flag or sigstore-bundle.json exists
  const useSigstore = opts.keyless || (!opts.key && await hasSigstoreBundle(dir));

  if (useSigstore) {
    const trustedIdentities: TrustedIdentity[] = (opts.trustedIdentity ?? []).map((ti) => {
      const eqIdx = ti.indexOf('=');
      if (eqIdx === -1) {
        console.error(`Error: --trusted-identity must be "issuer=subject", got "${ti}"`);
        process.exit(2);
      }
      return { issuer: ti.slice(0, eqIdx), subject: ti.slice(eqIdx + 1) };
    });

    let revocationKeys: Record<string, string> | undefined;
    if (opts.revocationKey) {
      const revPub = await readFile(opts.revocationKey, 'utf-8');
      const revKeyId = deriveKeyId(revPub);
      revocationKeys = { [revKeyId]: revPub };
    }

    const sigstoreOpts: SigstoreVerifyOptions = {
      trustedIdentities: trustedIdentities.length > 0 ? trustedIdentities : undefined,
      revocationKeys,
      revocationList,
      context,
      skipHardlinkCheck: opts.skipHardlinkCheck,
    };

    const result = await verifySigstoreEnvelope(dir, sigstoreOpts);
    const output = toCliOutput(result);
    console.log(JSON.stringify(output, null, 2));
    process.exit(result.valid ? 0 : 1);
    return;
  }

  // Ed25519 path
  if (!opts.key) {
    console.error('Error: --key <path> is required (or use --keyless for Sigstore verification)');
    process.exit(2);
  }

  const publicKey = await readFile(opts.key, 'utf-8');
  const keyId = deriveKeyId(publicKey);

  const trustedKeys: Record<string, string> = { [keyId]: publicKey };

  if (opts.revocationKey) {
    const revPub = await readFile(opts.revocationKey, 'utf-8');
    const revKeyId = deriveKeyId(revPub);
    trustedKeys[revKeyId] = revPub;
  }

  const result = await verifyEnvelope(dir, {
    trustedKeys,
    revocationList,
    context,
    skipHardlinkCheck: opts.skipHardlinkCheck,
  });

  const output = toCliOutput(result);
  console.log(JSON.stringify(output, null, 2));
  process.exit(result.valid ? 0 : 1);
}
