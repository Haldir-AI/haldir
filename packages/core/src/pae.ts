// HALDIR PAE — intentionally diverges from upstream DSSE v1.0.0.
//
// Upstream DSSE uses INT64LE for LEN(). Haldir uses ASCII decimal strings.
// This means Haldir envelopes are NOT interoperable with generic DSSE verifiers
// (sigstore, in-toto). Sign and verify within Haldir are consistent.
//
// Rationale: ASCII lengths are simpler, human-readable in debug output, and
// sufficient for our payload sizes. Sigstore path uses the sigstore library's
// own PAE. Interop with third-party DSSE tools is not a v1.0 goal.
//
// If interop becomes required, switch LEN() to 8-byte little-endian and
// re-sign all existing envelopes (breaking change).
export function encodePAE(payloadType: string, payload: Buffer): Buffer {
  const typeBytes = Buffer.from(payloadType, 'utf-8');
  const lenType = Buffer.from(`${typeBytes.length}`, 'ascii');
  const lenPayload = Buffer.from(`${payload.length}`, 'ascii');
  const sp = Buffer.from(' ');
  return Buffer.concat([
    Buffer.from('DSSEv1'),
    sp,
    lenType,
    sp,
    typeBytes,
    sp,
    lenPayload,
    sp,
    payload,
  ]);
}
