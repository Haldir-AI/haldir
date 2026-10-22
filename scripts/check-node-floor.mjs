// CVE-2026-111497 (Brotli request-body RCE) and the Oct 2026 TLS/CA fixes.
// Floors: 22.23.4, 24.22.1, 26.12.1. Node 20 and other lines are not patched.
const [major, minor, patch] = process.versions.node.split('.').map(Number);
const floors = {
  22: [23, 4],
  24: [22, 1],
  26: [12, 1],
};
const floor = floors[major];
if (!floor || minor < floor[0] || (minor === floor[0] && patch < floor[1])) {
  console.error(
    `Node ${process.version} is below the security floor for its line ` +
      `(22.23.4+, 24.22.1+, or 26.12.1+). ` +
      'Node 20 and older never receive CVE-2026-111497.',
  );
  process.exit(1);
}
console.log(`Node ${process.version} meets the security floor`);
