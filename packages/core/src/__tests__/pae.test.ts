import { describe, it, expect } from 'vitest';
import { encodePAE } from '../pae.js';

describe('encodePAE', () => {
  it('produces correct DSSE v1.0.0 PAE format', () => {
    const payloadType = 'application/vnd.haldir.attestation+json';
    const payload = Buffer.from('test payload');
    const result = encodePAE(payloadType, payload);

    const expected = `DSSEv1 ${payloadType.length} ${payloadType} ${payload.length} test payload`;
    expect(result.toString()).toBe(expected);
  });

  it('handles empty payload', () => {
    const payloadType = 'text/plain';
    const payload = Buffer.alloc(0);
    const result = encodePAE(payloadType, payload);

    expect(result.toString()).toBe('DSSEv1 10 text/plain 0 ');
  });

  it('uses byte length not character length for multibyte', () => {
    const payloadType = 'text/plain';
    const payload = Buffer.from('héllo', 'utf-8'); // é = 2 bytes
    const result = encodePAE(payloadType, payload);

    expect(result.toString()).toContain(` ${payload.length} `);
    expect(payload.length).toBe(6); // h(1) + é(2) + l(1) + l(1) + o(1)
  });

  it('different payloads produce different PAE', () => {
    const payloadType = 'text/plain';
    const pae1 = encodePAE(payloadType, Buffer.from('a'));
    const pae2 = encodePAE(payloadType, Buffer.from('b'));
    expect(Buffer.compare(pae1, pae2)).not.toBe(0);
  });
});
