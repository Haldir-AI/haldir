import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  generateKeyPair,
  createEnvelope,
  verifyEnvelope,
  createRevocationList
} from './packages/core/dist/index.js';

async function test() {
  console.log('🔒 Testing vetting report security hardening...\n');

  const testDir = join(tmpdir(), `haldir-security-test-${Date.now()}`);
  const skillDir = join(testDir, 'test-skill');
  await mkdir(skillDir, { recursive: true });

  await writeFile(join(skillDir, 'index.js'), 'export function test() { return "ok"; }');
  await writeFile(join(skillDir, 'SKILL.md'), '# Test\n');

  const { publicKey, privateKey, keyId } = await generateKeyPair();
  const revKeyPair = await generateKeyPair();

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
  console.log('✓ Test 1: Signing with vetting report...');
  await createEnvelope(skillDir, privateKey, {
    keyId,
    skill: { name: 'test', version: '1.0.0', type: 'skill.md' },
    vettingReport,
  });

  // Verify attestation includes vetting_report_hash
  const attestation = JSON.parse(await readFile(join(skillDir, '.vault/attestation.json'), 'utf-8'));
  if (!attestation.vetting_report_hash) {
    console.error('❌ Test 1 FAILED: attestation missing vetting_report_hash');
    process.exit(1);
  }
  console.log(`  ✓ Attestation includes vetting_report_hash: ${attestation.vetting_report_hash.substring(0, 20)}...`);

  // Verify vetting report is canonical JSON (no whitespace)
  const vettingBytes = await readFile(join(skillDir, '.vault/vetting-report.json'));
  const vettingString = vettingBytes.toString('utf-8');
  if (vettingString.includes('  ') || vettingString.includes('\n')) {
    console.error('❌ Test 1 FAILED: vetting report not canonical JSON (has indentation or newlines)');
    process.exit(1);
  }
  console.log('  ✓ Vetting report written as canonical JSON');

  // TEST 2: Verification succeeds with valid hash
  console.log('\n✓ Test 2: Verifying with valid vetting report hash...');
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

  const result = await verifyEnvelope(skillDir, {
    trustedKeys: { [keyId]: publicKey, [revKeyPair.keyId]: revKeyPair.publicKey },
    revocationList,
    context: 'install',
  });

  if (!result.valid) {
    console.error('❌ Test 2 FAILED: verification failed');
    console.error(result.errors);
    process.exit(1);
  }
  if (!result.vettingReport) {
    console.error('❌ Test 2 FAILED: vetting report not returned');
    process.exit(1);
  }
  console.log('  ✓ Verification succeeded');
  console.log(`  ✓ Vetting report returned (status: ${result.vettingReport.overall_status})`);

  // TEST 3: Tampering with vetting report detected
  console.log('\n✓ Test 3: Testing tampering detection...');
  const originalReport = JSON.parse(vettingBytes.toString('utf-8'));
  const tamperedReport = { ...originalReport, overall_status: 'pass' }; // Change flag to pass
  await writeFile(
    join(skillDir, '.vault/vetting-report.json'),
    JSON.stringify(tamperedReport)
  );

  const tamperResult = await verifyEnvelope(skillDir, {
    trustedKeys: { [keyId]: publicKey, [revKeyPair.keyId]: revKeyPair.publicKey },
    revocationList,
    context: 'install',
  });

  if (tamperResult.valid) {
    console.error('❌ Test 3 FAILED: tampered vetting report should fail verification');
    process.exit(1);
  }
  const integrityError = tamperResult.errors.find(e => e.code === 'E_INTEGRITY_MISMATCH' && e.message.includes('Vetting report hash mismatch'));
  if (!integrityError) {
    console.error('❌ Test 3 FAILED: should return E_INTEGRITY_MISMATCH for tampered report');
    console.error(tamperResult.errors);
    process.exit(1);
  }
  console.log('  ✓ Tampering detected: E_INTEGRITY_MISMATCH');
  console.log(`  ✓ Error message: ${integrityError.message}`);

  // TEST 4: Size limits enforced
  console.log('\n✓ Test 4: Testing size limits...');
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
      skill: { name: 'test', version: '1.0.0', type: 'skill.md' },
      vettingReport: hugeReport,
    });

    console.error('❌ Test 4 FAILED: should reject report with > 10 layers');
    process.exit(1);
  } catch (err) {
    if (!err.message.includes('Invalid vetting report')) {
      console.error('❌ Test 4 FAILED: wrong error message');
      console.error(err.message);
      process.exit(1);
    }
    console.log('  ✓ Size limit enforced: layers.max(10)');
  }

  console.log('\n✅ All security tests passed!');
  console.log('✅ Vetting report is now hash-bound and tamper-proof');
}

test().catch(err => {
  console.error('❌ Test failed:', err.message);
  process.exit(1);
});
