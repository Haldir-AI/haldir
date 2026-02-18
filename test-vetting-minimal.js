import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  generateKeyPair,
  createEnvelope,
} from './packages/core/dist/index.js';

async function test() {
  console.log('🧪 Minimal vetting report test...\n');

  const testDir = join(tmpdir(), `haldir-vetting-minimal-${Date.now()}`);
  const skillDir = join(testDir, 'test-skill');
  await mkdir(skillDir, { recursive: true });

  await writeFile(join(skillDir, 'index.js'), 'export function test() { return "ok"; }');
  await writeFile(join(skillDir, 'SKILL.md'), '# Test\n');

  const { publicKey, privateKey, keyId } = await generateKeyPair();

  const vettingReport = {
    schema_version: '1.0',
    vetting_timestamp: new Date().toISOString(),
    pipeline_version: '0.1.0',
    layers: [
      {
        layer: 1,
        name: 'scanner',
        status: 'flag',
        findings: [{ severity: 'high', category: 'test', message: 'test finding' }],
        summary: { critical: 0, high: 1, medium: 0, low: 0 },
      },
    ],
    overall_status: 'flag',
    publisher_note: 'test note',
  };

  // Test 1: Sign without vetting report
  await createEnvelope(skillDir, privateKey, {
    keyId,
    skill: { name: 'test', version: '1.0.0', type: 'skill.md' },
  });

  let content1;
  try {
    content1 = await readFile(join(skillDir, '.vault', 'vetting-report.json'), 'utf-8');
    console.error('❌ Test 1 FAILED: vetting-report.json should NOT exist');
    process.exit(1);
  } catch {
    console.log('✅ Test 1 PASSED: No vetting report when not provided');
  }

  // Test 2: Sign with vetting report
  await createEnvelope(skillDir, privateKey, {
    keyId,
    skill: { name: 'test', version: '1.0.0', type: 'skill.md' },
    vettingReport,
  });

  const content2 = await readFile(join(skillDir, '.vault', 'vetting-report.json'), 'utf-8');
  const parsed = JSON.parse(content2);

  if (parsed.overall_status !== 'flag') {
    console.error(`❌ Test 2 FAILED: Expected status 'flag', got '${parsed.overall_status}'`);
    process.exit(1);
  }

  if (!parsed.publisher_note || parsed.publisher_note !== 'test note') {
    console.error(`❌ Test 2 FAILED: Publisher note mismatch`);
    process.exit(1);
  }

  if (parsed.layers.length !== 1) {
    console.error(`❌ Test 2 FAILED: Expected 1 layer, got ${parsed.layers.length}`);
    process.exit(1);
  }

  if (parsed.layers[0].findings.length !== 1) {
    console.error(`❌ Test 2 FAILED: Expected 1 finding, got ${parsed.layers[0].findings.length}`);
    process.exit(1);
  }

  console.log('✅ Test 2 PASSED: Vetting report written correctly');
  console.log(`   - Schema: ${parsed.schema_version}`);
  console.log(`   - Status: ${parsed.overall_status}`);
  console.log(`   - Layers: ${parsed.layers.length}`);
  console.log(`   - Findings: ${parsed.layers[0].findings.length}`);
  console.log(`   - Note: ${parsed.publisher_note}`);

  console.log('\n✅ All tests passed! Vetting report feature working.');
}

test().catch(err => {
  console.error('❌ Test failed:', err.message);
  process.exit(1);
});
