#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-dry-run}"

if [[ "$MODE" != "dry-run" && "$MODE" != "live" ]]; then
  echo "Usage: bash scripts/publish.sh [dry-run|live]"
  exit 1
fi

LAYER_0=(core scanner auditor reviewer sandbox enforcer scheduler)
LAYER_1=(sdk pipeline registry)
LAYER_2=(cli)

echo "=== PREFLIGHT ==="
pnpm build
pnpm test -- --run
echo "Build + tests passed"

npm whoami --scope=@haldir 2>/dev/null || { echo "ERROR: Not logged in to @haldir npm org. Run: npm login --scope=@haldir"; exit 1; }

VERSIONS=$(pnpm -r exec -- node -p "require('./package.json').version" 2>/dev/null | sort -u)
VERSION_COUNT=$(echo "$VERSIONS" | wc -l | tr -d ' ')
if [[ "$VERSION_COUNT" -ne 1 ]]; then
  echo "ERROR: Version mismatch across packages:"
  echo "$VERSIONS"
  exit 1
fi
echo "Publishing v${VERSIONS} (mode: $MODE)"

publish_layer() {
  local layer_name=$1; shift
  local packages=("$@")
  echo ""
  echo "=== LAYER: $layer_name ==="
  for pkg in "${packages[@]}"; do
    echo "  @haldir/$pkg..."
    if [[ "$MODE" == "dry-run" ]]; then
      (cd "packages/$pkg" && pnpm publish --access public --no-git-checks --dry-run 2>&1 | head -5)
    else
      (cd "packages/$pkg" && pnpm publish --access public --no-git-checks)
      sleep 2
      npm info "@haldir/$pkg" version || { echo "FAILED: @haldir/$pkg not found on npm after publish"; exit 1; }
    fi
  done
}

publish_layer "0 (no internal deps)" "${LAYER_0[@]}"
publish_layer "1 (depends on layer 0)" "${LAYER_1[@]}"
publish_layer "2 (depends on layer 1)" "${LAYER_2[@]}"

echo ""
echo "=== DONE ($MODE) ==="
if [[ "$MODE" == "dry-run" ]]; then
  echo "Re-run with 'live' to actually publish: bash scripts/publish.sh live"
fi
