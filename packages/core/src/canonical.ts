import canonicalizeLib from 'canonicalize';

export function canonicalize(obj: unknown): string {
  const result = canonicalizeLib(obj);
  if (result === undefined) {
    throw new Error('Canonicalization failed: input produced undefined');
  }
  return result;
}

export function canonicalizeToBuffer(obj: unknown): Buffer {
  return Buffer.from(canonicalize(obj), 'utf-8');
}
