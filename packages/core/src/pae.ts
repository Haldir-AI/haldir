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
