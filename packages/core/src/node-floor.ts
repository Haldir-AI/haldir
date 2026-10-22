type SupportedMajor = 22 | 24 | 26;

function floorFor(major: SupportedMajor): readonly [number, number] {
  switch (major) {
    case 22:
      return [23, 4];
    case 24:
      return [22, 1];
    case 26:
      return [12, 1];
    default: {
      const neverMajor: never = major;
      throw new Error(`Unhandled Node major ${String(neverMajor)}`);
    }
  }
}

function supportedMajor(major: number): SupportedMajor | null {
  switch (major) {
    case 22:
    case 24:
    case 26:
      return major;
    default:
      return null;
  }
}

export function assertSupportedNode(version = process.versions.node): void {
  const [major, minor, patch] = version.split('.').map(Number);
  const supported = supportedMajor(major);
  const floor = supported === null ? undefined : floorFor(supported);
  if (
    floor === undefined ||
    minor === undefined ||
    patch === undefined ||
    minor < floor[0] ||
    (minor === floor[0] && patch < floor[1])
  ) {
    throw new Error(
      `Node ${version} is below the security floor for its line ` +
        '(22.23.4+, 24.22.1+, or 26.12.1+). ' +
        'Node 20 and older never receive CVE-2026-111497.',
    );
  }
}
