import { mkdir, writeFile, readFile, access } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  generateKeyPair,
  createEnvelope,
  verifyEnvelope,
  createRevocationList
} from './packages/core/dist/index.js';

async function test() {
  console.log('🧪 Testing vetting report workflow...\n');

  // Setup
  const testDir = join(tmpdir(), `haldir-vetting-test-${Date.now()}`);
  const skillDir = join(testDir, 'test-skill');
  await mkdir(skillDir, { recursive: true });

  // Create test skill
  await writeFile(
    join(skillDir, 'index.js'),
    'export function test() { return "ok"; }'
  );
  await writeFile(
    join(skillDir, 'SKILL.md'),
    '# Test Skill\n\nA simple test skill.'
  );

  console.log('✓ Created test skill');

  // Generate keypair
  const { publicKey, privateKey, keyId } = await generateKeyPair();
  console.log(`✓ Generated keypair (${keyId})`);

  // Create vetting report
  const vettingReport = {
    schema_version: '1.0',
    vetting_timestamp: new Date().toISOString(),
    pipeline_version: '0.1.0',
    layers: [
      {
        layer: 1,
        name: 'scanner',
        status: 'flag',
        duration_ms: 42,
        findings: [
          {
            severity: 'high',
            category: 'privilege_escalation',
            pattern_id: 'env_harvest_node',
            file: 'index.js',
            line: 2,
            message: 'Accesses environment variables (potential secret exposure)',
          },
        ],
        summary: {
          critical: 0,
          high: 1,
          medium: 0,
          low: 0,
        },
      },
    ],
    overall_status: 'flag',
    publisher_note: 'process.env used for configuration - reviewed and acceptable',
  };

  console.log('✓ Created vetting report (status: flag)');

  // Sign WITHOUT vetting report first
  await createEnvelope(skillDir, privateKey, {
    keyId,
    skill: {
      name: 'test-skill',
      version: '1.0.0',
      type: 'skill.md',
    },
  });

  console.log('✓ Signed skill WITHOUT vetting report');

  // Check vetting-report.json does NOT exist
  try {
    await access(join(skillDir, '.vault', 'vetting-report.json'));
    console.error('❌ vetting-report.json should NOT exist yet');
    process.exit(1);
  } catch {
    console.log('✓ Confirmed: vetting-report.json does NOT exist (as expected)');
  }

  // Now sign WITH vetting report
  await mkdir(join(skillDir, '.vault'), { recursive: true });
  await createEnvelope(skillDir, privateKey, {
    keyId,
    skill: {
      name: 'test-skill',
      version: '1.0.0',
      type: 'skill.md',
    },
    vettingReport,
  });

  console.log('✓ Signed skill WITH vetting report');

  // Check vetting-report.json exists
  try {
    const vettingReportPath = join(skillDir, '.vault', 'vetting-report.json');
    const vettingReportContent = await readFile(vettingReportPath, 'utf-8');
    const parsed = JSON.parse(vettingReportContent);
    console.log('✓ vetting-report.json exists in .vault/');
    console.log(`  - Schema version: ${parsed.schema_version}`);
    console.log(`  - Overall status: ${parsed.overall_status}`);
    console.log(`  - Layers: ${parsed.layers.length}`);
    console.log(`  - Findings in layer 1: ${parsed.layers[0].findings.length}`);
    console.log(`  - Publisher note: ${parsed.publisher_note}`);

    // Validate structure
    if (parsed.overall_status !== 'flag') {
      throw new Error(`Expected status 'flag', got '${parsed.overall_status}'`);
    }
    if (parsed.layers[0].findings.length !== 1) {
      throw new Error(`Expected 1 finding, got ${parsed.layers[0].findings.length}`);
    }
    if (parsed.layers[0].findings[0].severity !== 'high') {
      throw new Error(`Expected severity 'high', got '${parsed.layers[0].findings[0].severity}'`);
    }
  } catch (err) {
    console.error('❌ Failed to validate vetting-report.json:', err.message);
    process.exit(1);
  }

  // Create revocation list with separate signing key
  const revKeyPair = await generateKeyPair();
  const revocationList = await createRevocationList(
    {
      schema_version: '1.0',
      sequence_number: 1,
      issued_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      next_update: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      entries: [],
    },
    revKeyPair.privateKey
  );

  console.log('✓ Created revocation list');

  // Verify signature with proper key mapping
  const result = await verifyEnvelope(skillDir, {
    trustedKeys: {
      [keyId]: publicKey,
      [revKeyPair.keyId]: revKeyPair.publicKey,
    },
    revocationList,
    context: 'install',
  });

  console.log('\n✅ Verification result:');
  console.log(`  - Valid: ${result.valid}`);
  console.log(`  - Trust level: ${result.trustLevel}`);
  console.log(`  - Has vetting report: ${!!result.vettingReport}`);
  if (result.vettingReport) {
    console.log(`  - Vetting status: ${result.vettingReport.overall_status}`);
    console.log(`  - Vetting layers: ${result.vettingReport.layers.length}`);
    console.log(`  - Findings: ${result.vettingReport.layers[0].findings.length}`);
    console.log(`  - Publisher note: ${result.vettingReport.publisher_note}`);
  }

  if (!result.valid) {
    console.error('\n❌ Verification failed:', result.errors);
    process.exit(1);
  }

  if (!result.vettingReport) {
    console.error('\n❌ Vetting report not found in verification result');
    process.exit(1);
  }

  if (result.vettingReport.overall_status !== 'flag') {
    console.error('\n❌ Unexpected vetting status:', result.vettingReport.overall_status);
    process.exit(1);
  }

  console.log('\n✅ All vetting report tests passed!');
  console.log('✅ Vetting report transparency feature working correctly');
}

test().catch(err => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
