#!/bin/bash
set -e

echo "🧪 Testing vetting report workflow..."

# Setup
TMPDIR=$(mktemp -d)
SKILL_DIR="$TMPDIR/test-skill"
KEY_DIR="$TMPDIR/keys"
REPORT_FILE="$TMPDIR/vetting-report.json"

mkdir -p "$SKILL_DIR" "$KEY_DIR"

# Create test skill with a suspicious pattern
cat > "$SKILL_DIR/index.js" <<'EOF'
export async function weather(city) {
  const API_KEY = process.env.OPENWEATHER_API_KEY;
  const url = `https://api.openweathermap.org/data/2.5/weather?q=${city}&appid=${API_KEY}`;
  const response = await fetch(url);
  return await response.json();
}
EOF

cat > "$SKILL_DIR/SKILL.md" <<'EOF'
# Weather Skill

Gets current weather for a city.
EOF

echo "✓ Created test skill"

# Generate keypair
node packages/cli/dist/index.js keygen --output "$KEY_DIR"
echo "✓ Generated keypair"

# Scan the skill
echo "📊 Running scan..."
node packages/cli/dist/index.js scan "$SKILL_DIR" --json > "$TMPDIR/scan-raw.json"
SCAN_STATUS=$(cat "$TMPDIR/scan-raw.json" | node -e "console.log(JSON.parse(require('fs').readFileSync(0, 'utf-8')).status)")
echo "Scan status: $SCAN_STATUS"

# Create vetting report JSON manually
cat > "$REPORT_FILE" <<EOF
{
  "schema_version": "1.0",
  "vetting_timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")",
  "pipeline_version": "0.1.0",
  "layers": [
    {
      "layer": 1,
      "name": "scanner",
      "status": "$SCAN_STATUS",
      "duration_ms": 42,
      "findings": $(cat "$TMPDIR/scan-raw.json" | node -e "const data = JSON.parse(require('fs').readFileSync(0, 'utf-8')); console.log(JSON.stringify(data.findings.slice(0, 3), null, 2))"),
      "summary": $(cat "$TMPDIR/scan-raw.json" | node -e "const data = JSON.parse(require('fs').readFileSync(0, 'utf-8')); console.log(JSON.stringify(data.summary, null, 2))")
    }
  ],
  "overall_status": "$SCAN_STATUS",
  "publisher_note": "process.env used for API key retrieval - acceptable for weather service"
}
EOF

echo "✓ Created vetting report"

# Sign with vetting report
echo "🔏 Signing with vetting report..."
node packages/cli/dist/index.js sign "$SKILL_DIR" \
  --key "$KEY_DIR/haldir.key" \
  --name "weather-skill" \
  --skill-version "1.0.0" \
  --type "skill.md" \
  --vetting-report "$REPORT_FILE"

echo "✓ Signed skill with vetting report"

# Verify the signature
echo "✅ Verifying signature..."
VERIFY_OUTPUT=$(node packages/cli/dist/index.js verify "$SKILL_DIR" --key "$KEY_DIR/haldir.pub")
echo "$VERIFY_OUTPUT" | node -e "const data = JSON.parse(require('fs').readFileSync(0, 'utf-8')); console.log('Valid:', data.valid); console.log('Has vetting report:', !!data.vettingReport); console.log('Vetting status:', data.vettingReport?.overall_status);"

# Check vetting-report.json exists in .vault/
if [ -f "$SKILL_DIR/.vault/vetting-report.json" ]; then
  echo "✓ vetting-report.json exists in .vault/"
  echo "Vetting report contents:"
  cat "$SKILL_DIR/.vault/vetting-report.json" | node -e "const data = JSON.parse(require('fs').readFileSync(0, 'utf-8')); console.log('  Schema version:', data.schema_version); console.log('  Overall status:', data.overall_status); console.log('  Layers:', data.layers.length); console.log('  Publisher note:', data.publisher_note);"
else
  echo "❌ vetting-report.json NOT found in .vault/"
  exit 1
fi

# Cleanup
rm -rf "$TMPDIR"

echo ""
echo "✅ All vetting report tests passed!"
