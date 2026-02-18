import type { PatternBundle } from '@haldir/scanner';

const SEMVER_RE = /^\d+\.\d+\.\d+$/;

export async function fetchPatternBundle(
  registryUrl: string,
  version?: string,
): Promise<PatternBundle> {
  const base = registryUrl.replace(/\/+$/, '');

  if (version && !SEMVER_RE.test(version)) {
    throw new Error(`Invalid pattern version: ${version} (expected semver like 1.0.0)`);
  }

  const url = version
    ? `${base}/v1/scanner/patterns/${version}`
    : `${base}/v1/scanner/patterns`;

  const res = await fetch(url, {
    headers: { 'Accept': 'application/json' },
    signal: AbortSignal.timeout(10_000),
  });

  if (!res.ok) {
    throw new Error(`Registry returned ${res.status}: ${res.statusText}`);
  }

  return res.json() as Promise<PatternBundle>;
}
