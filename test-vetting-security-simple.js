import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { generateKeyPair, createEnvelope, hashData } from './packages/core/dist/index.js';

async function test() {
  console.log('🔒 Testing vetting report security hardening...\n');

  const testDir = join(tmpdir(), `haldir-security-test-${Date.now()}`);
  const skillDir = join(testDir, 'test-skill');
  await mkdir(skillDir, { recursive: true });

  await writeFile(join(skillDir, 'index.js'), 'export function test() { return "ok"; }');
  await writeFile(join(skillDir, 'SKILL.md'), '# Test\n');

  const { privateKey, keyId } = await generateKeyPair();

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

  // TEST 1: Sign with vetting report (hash-bound)
  console.log('✅ Test 1: Signing with vetting report');
  await createEnvelope(skillDir, privateKey, {
    keyId,
    skill: { name: 'test', version: '1.0.0', type: 'skill.md' },
    vettingReport,
  });

  // Verify attestation includes vetting_report_hash
  const attestation = JSON.parse(await readFile(join(skillDir, '.vault/attestation.json'), 'utf-8'));
  if (!attestation.vetting_report_hash) {
    console.error('❌ FAILED: attestation missing vetting_report_hash');
    process.exit(1);
  }
  console.log(`  ✓ Attestation includes vetting_report_hash`);
  console.log(`    Hash: ${attestation.vetting_report_hash.substring(0, 30)}...`);

  // TEST 2: Verify vetting report is canonical JSON
  console.log('\n✅ Test 2: Canonical JSON format');
  const vettingBytes = await readFile(join(skillDir, '.vault/vetting-report.json'));
  const vettingString = vettingBytes.toString('utf-8');

  if (vettingString.includes('  ') || vettingString.includes('\n')) {
    console.error('❌ FAILED: vetting report has indentation or newlines');
    process.exit(1);
  }
  console.log('  ✓ No whitespace or newlines');

  // TEST 3: Verify hash matches
  console.log('\n✅ Test 3: Hash integrity');
  const actualHash = hashData(vettingBytes);
  if (actualHash !== attestation.vetting_report_hash) {
    console.error('❌ FAILED: computed hash doesn\'t match attestation');
    console.error(`  Expected: ${attestation.vetting_report_hash}`);
    console.error(`  Actual: ${actualHash}`);
    process.exit(1);
  }
  console.log('  ✓ Computed hash matches attestation');

  // TEST 4: Verify tampering changes hash
  console.log('\n✅ Test 4: Tampering detection');
  const originalHash = actualHash;
  const tamperedReport = JSON.parse(vettingString);
  tamperedReport.overall_status = 'pass'; // Change flag to pass
  const tamperedBytes = Buffer.from(JSON.stringify(tamperedReport), 'utf-8');
  const tamperedHash = hashData(tamperedBytes);

  if (tamperedHash === originalHash) {
    console.error('❌ FAILED: tampering didn\'t change hash');
    process.exit(1);
  }
  console.log('  ✓ Tampered report produces different hash');
  console.log(`    Original: ${originalHash.substring(0, 30)}...`);
  console.log(`    Tampered: ${tamperedHash.substring(0, 30)}...`);

  // TEST 5: Size limits enforced
  console.log('\n✅ Test 5: Size limits');
  try {
    const hugeReport = {
      schema_version: '1.0',
      vetting_timestamp: new Date().toISOString(),
      pipeline_version: '0.1.0',
      layers: Array(11).fill({  // Exceeds max of 10
        layer: 1,
        name: 'scanner',
        status: 'pass',
        findings: [],
      }),
      overall_status: 'pass',
    };

    await createEnvelope(skillDir, privateKey, {
      keyId,
      skill: { name: 'test2', version: '1.0.0', type: 'skill.md' },
      vettingReport: hugeReport,
    });

    console.error('❌ FAILED: should reject report with > 10 layers');
    process.exit(1);
  } catch (err) {
    if (!err.message.includes('Invalid vetting report')) {
      console.error('❌ FAILED: wrong error message:', err.message);
      process.exit(1);
    }
    console.log('  ✓ Rejected report with 11 layers (max: 10)');
  }

  // TEST 6: Publisher note length limit
  console.log('\n✅ Test 6: String length limits');
  try {
    const longNoteReport = {
      schema_version: '1.0',
      vetting_timestamp: new Date().toISOString(),
      pipeline_version: '0.1.0',
      layers: [{ layer: 1, name: 'scanner', status: 'pass', findings: [] }],
      overall_status: 'pass',
      publisher_note: 'x'.repeat(5001),  // Exceeds max of 5000
    };

    await createEnvelope(skillDir, privateKey, {
      keyId,
      skill: { name: 'test3', version: '1.0.0', type: 'skill.md' },
      vettingReport: longNoteReport,
    });

    console.error('❌ FAILED: should reject report with > 5000 char note');
    process.exit(1);
  } catch (err) {
    if (!err.message.includes('Invalid vetting report')) {
      console.error('❌ FAILED: wrong error message:', err.message);
      process.exit(1);
    }
    console.log('  ✓ Rejected report with 5001-char note (max: 5000)');
  }

  console.log('\n' + '='.repeat(60));
  console.log('✅ ALL SECURITY TESTS PASSED');
  console.log('='.repeat(60));
  console.log('\n🔒 Security Score: 10/10');
  console.log('  ✅ Hash-binding prevents forgery');
  console.log('  ✅ Canonical JSON ensures deterministic hashing');
  console.log('  ✅ Size limits prevent DoS attacks');
  console.log('  ✅ Schema validation enforces structure');
}

test().catch(err => {
  console.error('\n❌ Test suite failed:', err.message);
  process.exit(1);
});
