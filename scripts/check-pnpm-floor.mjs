import { execSync } from 'node:child_process';

// CVE-2026-101043, CVE-2026-82392, CVE-2026-82393.
// 10.x needs >=10.34.5 and 11.x needs >=11.11.0. This repo stays on pnpm 12,
// where those fixes shipped before 12.0.0. Prereleases are below the floor.
const raw = execSync('pnpm --version', { encoding: 'utf8' }).trim();
const major = Number(raw.split('.')[0]);
const prerelease = raw.includes('-');
if (prerelease || !Number.isInteger(major) || major < 12) {
  console.error(
    `pnpm ${raw} is below the security floor >=12.0.0 ` +
      '(CVE-2026-101043, CVE-2026-82392, CVE-2026-82393).',
  );
  process.exit(1);
}
console.log(`pnpm ${raw} meets the security floor >=12.0.0`);
