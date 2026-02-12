import { verifyEnvelope, verifySigstoreEnvelope, hasSigstoreBundle } from '@haldir/core';
import type {
  KeyRing,
  SignedRevocationList,
  VerifyResult,
  TrustedIdentity,
  SigstoreVerifyResult,
} from '@haldir/core';

export interface HaldirOptions {
  trustedKeys?: KeyRing;
  trustedIdentities?: TrustedIdentity[];
  revocationKeys?: KeyRing;
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
  private trustedIdentities?: TrustedIdentity[];
  private revocationKeys?: KeyRing;

  constructor(options: HaldirOptions) {
    this.trustedKeys = options.trustedKeys ?? {};
    this.trustedIdentities = options.trustedIdentities;
    this.revocationKeys = options.revocationKeys;
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

  async verifySigstore(skillDir: string, options: HaldirVerifyOptions): Promise<SigstoreVerifyResult> {
    return verifySigstoreEnvelope(skillDir, {
      trustedIdentities: this.trustedIdentities,
      revocationKeys: this.revocationKeys,
      revocationList: options.revocationList,
      lastValidRevocationList: options.lastValidRevocationList,
      cachedSequenceNumber: options.cachedSequenceNumber,
      context: options.context,
      skipHardlinkCheck: options.skipHardlinkCheck,
    });
  }

  async autoVerify(skillDir: string, options: HaldirVerifyOptions): Promise<VerifyResult | SigstoreVerifyResult> {
    const isSigstore = await hasSigstoreBundle(skillDir);
    if (isSigstore) {
      return this.verifySigstore(skillDir, options);
    }
    return this.verify(skillDir, options);
  }
}

export type {
  KeyRing,
  SignedRevocationList,
  VerifyResult,
  TrustedIdentity,
  SigstoreVerifyResult,
} from '@haldir/core';
