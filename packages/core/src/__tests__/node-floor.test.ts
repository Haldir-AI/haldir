import { describe, expect, it } from 'vitest';
import { assertSupportedNode } from '../node-floor.js';

describe('assertSupportedNode', () => {
  it('accepts patched releases on each supported line', () => {
    expect(() => assertSupportedNode('22.23.4')).not.toThrow();
    expect(() => assertSupportedNode('22.24.0')).not.toThrow();
    expect(() => assertSupportedNode('24.22.1')).not.toThrow();
    expect(() => assertSupportedNode('24.23.0')).not.toThrow();
    expect(() => assertSupportedNode('26.12.1')).not.toThrow();
    expect(() => assertSupportedNode('26.13.0')).not.toThrow();
  });

  it('rejects versions below the floor for that line', () => {
    expect(() => assertSupportedNode('22.23.3')).toThrow(/CVE-2026-111497/);
    expect(() => assertSupportedNode('24.22.0')).toThrow(/security floor/);
    expect(() => assertSupportedNode('24.21.9')).toThrow(/security floor/);
    expect(() => assertSupportedNode('26.12.0')).toThrow(/security floor/);
  });

  it('rejects Node 20 and unsupported majors', () => {
    expect(() => assertSupportedNode('20.19.5')).toThrow(/CVE-2026-111497/);
    expect(() => assertSupportedNode('18.20.8')).toThrow(/security floor/);
    expect(() => assertSupportedNode('23.11.0')).toThrow(/security floor/);
    expect(() => assertSupportedNode('25.0.0')).toThrow(/security floor/);
  });
});
