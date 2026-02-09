import { generateKeyPairSync, createHash, sign as cryptoSign, verify as cryptoVerify, timingSafeEqual, KeyObject, createPublicKey, createPrivateKey } from 'node:crypto';
import type { KeyPair } from './types.js';

const HASH_STRING_RE = /^sha256:[0-9a-f]{64}$/;

export function generateKeyPair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const keyId = deriveKeyId(publicKey);
  return { publicKey, privateKey, keyId };
}

export function deriveKeyId(keyPem: string): string {
  const keyObj = createPublicKey(keyPem);
  const rawBytes = keyObj.export({ type: 'spki', format: 'der' });
  const hash = createHash('sha256').update(rawBytes).digest('hex');
  return hash.slice(0, 32);
}

export function sign(data: Buffer, privateKeyPem: string): Buffer {
  const keyObj = createPrivateKey(privateKeyPem);
  return Buffer.from(cryptoSign(undefined, data, keyObj));
}

export function verify(data: Buffer, signature: Buffer, publicKeyPem: string): boolean {
  const keyObj = createPublicKey(publicKeyPem);
  return cryptoVerify(undefined, data, keyObj, signature);
}

export function hashData(data: Buffer): string {
  const hex = createHash('sha256').update(data).digest('hex');
  return `sha256:${hex}`;
}

export function safeHashCompare(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export function parseHashString(hash: string): { algorithm: string; hex: string } {
  if (!HASH_STRING_RE.test(hash)) {
    throw new Error(`Invalid hash string: ${hash}`);
  }
  const colonIdx = hash.indexOf(':');
  return {
    algorithm: hash.slice(0, colonIdx),
    hex: hash.slice(colonIdx + 1),
  };
}

export function base64urlEncode(buf: Buffer): string {
  return buf.toString('base64url');
}

export function base64urlDecode(str: string): Buffer {
  return Buffer.from(str, 'base64url');
}
