import { readFile, writeFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { VAULT_DIR } from './types.js';
import type { Bundle } from 'sigstore';

export const SIGSTORE_BUNDLE_FILE = 'sigstore-bundle.json';

export interface SigstoreSignOptions {
  identityToken?: string;
  fulcioURL?: string;
  rekorURL?: string;
}

export async function signWithSigstore(
  payload: Buffer,
  options: SigstoreSignOptions = {}
): Promise<Bundle> {
  const { sign } = await import('sigstore');
  const bundle = await sign(payload, {
    identityToken: options.identityToken,
    fulcioURL: options.fulcioURL,
    rekorURL: options.rekorURL,
    tlogUpload: true,
  });
  return bundle;
}

export async function verifyWithSigstore(
  bundle: Bundle,
  payload: Buffer,
  options: {
    certificateIssuer?: string;
    certificateIdentityEmail?: string;
    certificateIdentityURI?: string;
    tlogThreshold?: number;
    ctLogThreshold?: number;
  } = {}
): Promise<SigstoreSignerInfo> {
  const { verify } = await import('sigstore');
  const signer = await verify(bundle, payload, {
    certificateIssuer: options.certificateIssuer,
    certificateIdentityEmail: options.certificateIdentityEmail,
    certificateIdentityURI: options.certificateIdentityURI,
    tlogThreshold: options.tlogThreshold ?? 1,
    ctLogThreshold: options.ctLogThreshold ?? 0,
  });

  return extractSignerInfo(signer);
}

export interface SigstoreSignerInfo {
  identity: string;
  issuer: string;
}

export async function writeSigstoreBundle(
  skillDir: string,
  bundle: Bundle
): Promise<void> {
  const bundlePath = join(skillDir, VAULT_DIR, SIGSTORE_BUNDLE_FILE);
  await writeFile(bundlePath, JSON.stringify(bundle, null, 2) + '\n');
}

export async function readSigstoreBundle(
  skillDir: string
): Promise<Bundle | null> {
  const bundlePath = join(skillDir, VAULT_DIR, SIGSTORE_BUNDLE_FILE);
  try {
    const data = await readFile(bundlePath, 'utf-8');
    const parsed = JSON.parse(data);
    if (
      !parsed ||
      typeof parsed !== 'object' ||
      !('verificationMaterial' in parsed) ||
      typeof parsed.verificationMaterial !== 'object'
    ) {
      return null;
    }
    const vm = parsed.verificationMaterial;
    if (typeof vm !== 'object' || vm === null) return null;
    const hasKeyMaterial = 'publicKey' in vm || 'x509CertificateChain' in vm || 'certificate' in vm || 'tlogEntries' in vm;
    if (!hasKeyMaterial) return null;
    const hasSignature = parsed.messageSignature || parsed.dsseEnvelope || parsed.content;
    if (!hasSignature) return null;
    return parsed as Bundle;
  } catch {
    return null;
  }
}

export async function hasSigstoreBundle(skillDir: string): Promise<boolean> {
  const bundlePath = join(skillDir, VAULT_DIR, SIGSTORE_BUNDLE_FILE);
  try {
    await stat(bundlePath);
    return true;
  } catch {
    return false;
  }
}

function extractSignerInfo(signer: unknown): SigstoreSignerInfo {
  const s = signer as Record<string, unknown>;

  let identity = 'unknown';
  let issuer = 'unknown';

  // Signer type: { key: KeyObject, identity?: { subjectAlternativeName?, extensions?: { issuer? } } }
  const id = s?.identity as Record<string, unknown> | undefined;
  if (id?.subjectAlternativeName && typeof id.subjectAlternativeName === 'string') {
    identity = id.subjectAlternativeName;
  }

  const extensions = id?.extensions as Record<string, string> | undefined;
  if (extensions?.issuer) {
    issuer = extensions.issuer;
  }

  return { identity, issuer };
}
