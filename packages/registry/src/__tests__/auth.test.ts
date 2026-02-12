import { describe, it, expect } from 'vitest';
import { hashApiKey } from '../auth/middleware.js';

describe('hashApiKey', () => {
  it('produces consistent SHA-256 hex digest', () => {
    const hash1 = hashApiKey('test-key');
    const hash2 = hashApiKey('test-key');
    expect(hash1).toBe(hash2);
    expect(hash1).toHaveLength(64);
  });

  it('produces different hashes for different keys', () => {
    expect(hashApiKey('key-a')).not.toBe(hashApiKey('key-b'));
  });
});
