import { verifyEnvelope } from '@haldir/core';
import type { KeyRing, SignedRevocationList, VerifyResult } from '@haldir/core';

export interface HaldirOptions {
  trustedKeys: KeyRing;
}

export interface HaldirVerifyOptions {
  context: 'install' | 'runtime';
  revocationList?: SignedRevocationList;
  lastValidRevocationList?: SignedRevocationList;
  cachedSequenceNumber?: number;
  skipHardlinkCheck?: boolean;
}

export class Haldir {
  private trustedKeys: KeyRing;

  constructor(options: HaldirOptions) {
    this.trustedKeys = options.trustedKeys;
  }

  async verify(skillDir: string, options: HaldirVerifyOptions): Promise<VerifyResult> {
    return verifyEnvelope(skillDir, {
      trustedKeys: this.trustedKeys,
      revocationList: options.revocationList,
      lastValidRevocationList: options.lastValidRevocationList,
      cachedSequenceNumber: options.cachedSequenceNumber,
      context: options.context,
      skipHardlinkCheck: options.skipHardlinkCheck,
    });
  }
}

export type { KeyRing, SignedRevocationList, VerifyResult } from '@haldir/core';
