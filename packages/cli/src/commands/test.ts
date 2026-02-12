import { mkdtemp, mkdir, writeFile, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// CLI path - when built, this file is part of dist/index.js
// So we need to reference dist/index.js (the file containing this code)
const CLI_PATH = resolve(__dirname, "index.js");

interface TestResult {
  name: string;
  passed: boolean;
  duration: number;
  error?: string;
}

interface TestSuite {
  total: number;
  passed: number;
  failed: number;
  duration: number;
  tests: TestResult[];
}

/**
 * Run built-in test suite
 */
export async function runTestSuite(): Promise<void> {
  console.log("🧪 Haldir End-to-End Test Suite\n");

  const suite: TestSuite = {
    total: 0,
    passed: 0,
    failed: 0,
    duration: 0,
    tests: [],
  };

  const startTime = Date.now();

  // Test 1: Keygen
  await runTest(suite, "Generate keypair", testKeygen);

  // Test 2: Sign simple skill
  await runTest(suite, "Sign valid skill", testSignSimpleSkill);

  // Test 3: Verify valid skill
  await runTest(suite, "Verify valid signature", testVerifyValid);

  // Test 4: Detect tampered file
  await runTest(suite, "Detect modified file", testDetectTamper);

  // Test 5: Detect extra file
  await runTest(suite, "Detect extra file", testDetectExtraFile);

  // Test 6: Wrong public key
  await runTest(suite, "Reject wrong public key", testWrongKey);

  // Test 7: Revocation
  await runTest(suite, "Revocation enforcement", testRevocation);

  suite.duration = Date.now() - startTime;

  // Print results
  console.log("\n" + "=".repeat(60));
  console.log(`\n📊 Test Results\n`);
  console.log(`Total:    ${suite.total}`);
  console.log(`Passed:   ${suite.passed} ✓`);
  console.log(`Failed:   ${suite.failed} ✗`);
  console.log(`Duration: ${suite.duration}ms\n`);

  if (suite.failed > 0) {
    console.log("❌ Failed tests:\n");
    suite.tests
      .filter((t) => !t.passed)
      .forEach((t) => {
        console.log(`  • ${t.name}`);
        console.log(`    ${t.error}\n`);
      });

    process.exit(1);
  } else {
    console.log("✅ All tests passed!\n");
  }
}

async function runTest(
  suite: TestSuite,
  name: string,
  testFn: () => Promise<void>
): Promise<void> {
  const startTime = Date.now();
  suite.total++;

  try {
    await testFn();
    const duration = Date.now() - startTime;
    suite.passed++;
    suite.tests.push({ name, passed: true, duration });
    console.log(`✓ ${name} (${duration}ms)`);
  } catch (error) {
    const duration = Date.now() - startTime;
    suite.failed++;
    suite.tests.push({
      name,
      passed: false,
      duration,
      error: error instanceof Error ? error.message : String(error),
    });
    console.log(`✗ ${name} (${duration}ms)`);
  }
}

// Individual test functions

async function testKeygen() {
  const tempDir = await mkdtemp(join(tmpdir(), "haldir-test-"));

  try {
    await execFileAsync("node", [
      CLI_PATH,
      "keygen",
      "--output",
      tempDir,
    ]);

    // Check files exist
    const keyPath = join(tempDir, "haldir.key");
    const pubPath = join(tempDir, "haldir.pub");

    await readFile(keyPath);
    await readFile(pubPath);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

async function testSignSimpleSkill() {
  const tempDir = await mkdtemp(join(tmpdir(), "haldir-test-"));

  try {
    // Generate keys
    await execFileAsync("node", [
      CLI_PATH,
      "keygen",
      "--output",
      tempDir,
    ]);

    // Create simple skill
    const skillDir = join(tempDir, "skill");
    await mkdir(skillDir, { recursive: true });
    await writeFile(
      join(skillDir, "SKILL.md"),
      "# Test Skill\n\nTest description."
    );
    await writeFile(join(skillDir, "skill.js"), 'console.log("test");');

    // Sign it
    const { stdout } = await execFileAsync("node", [
      CLI_PATH,
      "sign",
      skillDir,
      "--key",
      join(tempDir, "haldir.key"),
    ]);

    if (!stdout.includes("✓")) {
      throw new Error("Sign command did not succeed");
    }
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

async function testVerifyValid() {
  const tempDir = await mkdtemp(join(tmpdir(), "haldir-test-"));

  try {
    await execFileAsync("node", [
      CLI_PATH,
      "keygen",
      "--output",
      tempDir,
    ]);

    const skillDir = join(tempDir, "skill");
    await mkdir(skillDir, { recursive: true });
    await writeFile(join(skillDir, "SKILL.md"), "# Test");
    await writeFile(join(skillDir, "skill.js"), "console.log('test');");

    await execFileAsync("node", [
      CLI_PATH,
      "sign",
      skillDir,
      "--key",
      join(tempDir, "haldir.key"),
    ]);

    const { stdout } = await execFileAsync("node", [
      CLI_PATH,
      "verify",
      skillDir,
      "--key",
      join(tempDir, "haldir.pub"),
      "--context",
      "runtime",
    ]);

    const result = JSON.parse(stdout);
    if (!result.valid) {
      throw new Error(`Verification failed: ${JSON.stringify(result.errors)}`);
    }
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

async function testDetectTamper() {
  const tempDir = await mkdtemp(join(tmpdir(), "haldir-test-"));

  try {
    await execFileAsync("node", [
      CLI_PATH,
      "keygen",
      "--output",
      tempDir,
    ]);

    const skillDir = join(tempDir, "skill");
    await mkdir(skillDir, { recursive: true });
    await writeFile(join(skillDir, "SKILL.md"), "# Test");
    await writeFile(join(skillDir, "skill.js"), "console.log('test');");

    await execFileAsync("node", [
      CLI_PATH,
      "sign",
      skillDir,
      "--key",
      join(tempDir, "haldir.key"),
    ]);

    // Tamper with file
    await writeFile(join(skillDir, "skill.js"), "console.log('tampered');");

    try {
      await execFileAsync("node", [
        CLI_PATH,
        "verify",
        skillDir,
        "--key",
        join(tempDir, "haldir.pub"),
        "--context",
        "runtime",
      ]);
      throw new Error("Verification should have failed");
    } catch (error: any) {
      const result = JSON.parse(error.stdout || "{}");
      if (result.errors?.[0]?.code !== "E_INTEGRITY_MISMATCH") {
        throw new Error(`Expected E_INTEGRITY_MISMATCH, got ${result.errors?.[0]?.code}`);
      }
    }
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

async function testDetectExtraFile() {
  const tempDir = await mkdtemp(join(tmpdir(), "haldir-test-"));

  try {
    await execFileAsync("node", [
      CLI_PATH,
      "keygen",
      "--output",
      tempDir,
    ]);

    const skillDir = join(tempDir, "skill");
    await mkdir(skillDir, { recursive: true });
    await writeFile(join(skillDir, "SKILL.md"), "# Test");
    await writeFile(join(skillDir, "skill.js"), "console.log('test');");

    await execFileAsync("node", [
      CLI_PATH,
      "sign",
      skillDir,
      "--key",
      join(tempDir, "haldir.key"),
    ]);

    // Add extra file
    await writeFile(join(skillDir, "backdoor.js"), "console.log('evil');");

    try {
      await execFileAsync("node", [
        CLI_PATH,
        "verify",
        skillDir,
        "--key",
        join(tempDir, "haldir.pub"),
        "--context",
        "runtime",
      ]);
      throw new Error("Verification should have failed");
    } catch (error: any) {
      const result = JSON.parse(error.stdout || "{}");
      if (result.errors?.[0]?.code !== "E_EXTRA_FILES") {
        throw new Error(`Expected E_EXTRA_FILES, got ${result.errors?.[0]?.code}`);
      }
    }
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

async function testWrongKey() {
  const tempDir = await mkdtemp(join(tmpdir(), "haldir-test-"));

  try {
    await execFileAsync("node", [
      CLI_PATH,
      "keygen",
      "--output",
      tempDir,
    ]);

    const tempDir2 = await mkdtemp(join(tmpdir(), "haldir-test-"));
    await execFileAsync("node", [
      CLI_PATH,
      "keygen",
      "--output",
      tempDir2,
    ]);

    const skillDir = join(tempDir, "skill");
    await mkdir(skillDir, { recursive: true });
    await writeFile(join(skillDir, "SKILL.md"), "# Test");
    await writeFile(join(skillDir, "skill.js"), "console.log('test');");

    await execFileAsync("node", [
      CLI_PATH,
      "sign",
      skillDir,
      "--key",
      join(tempDir, "haldir.key"),
    ]);

    try {
      await execFileAsync("node", [
        CLI_PATH,
        "verify",
        skillDir,
        "--key",
        join(tempDir2, "haldir.pub"),
        "--context",
        "runtime",
      ]);
      throw new Error("Verification should have failed");
    } catch (error: any) {
      const result = JSON.parse(error.stdout || "{}");
      if (result.errors?.[0]?.code !== "E_UNKNOWN_KEY") {
        throw new Error(`Expected E_UNKNOWN_KEY, got ${result.errors?.[0]?.code}`);
      }
    }

    await rm(tempDir2, { recursive: true, force: true });
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

async function testRevocation() {
  const tempDir = await mkdtemp(join(tmpdir(), "haldir-test-"));

  try {
    await execFileAsync("node", [
      CLI_PATH,
      "keygen",
      "--output",
      tempDir,
    ]);

    const skillDir = join(tempDir, "skill");
    await mkdir(skillDir, { recursive: true });
    await writeFile(join(skillDir, "SKILL.md"), "# Test");
    await writeFile(join(skillDir, "skill.js"), "console.log('test');");

    await execFileAsync("node", [
      CLI_PATH,
      "sign",
      skillDir,
      "--key",
      join(tempDir, "haldir.key"),
      "--name",
      "test-skill",
      "--skill-version",
      "1.0.0",
    ]);

    const revocationPath = join(tempDir, "revocation.json");
    await execFileAsync("node", [
      CLI_PATH,
      "revoke",
      "test-skill@1.0.0",
      "--key",
      join(tempDir, "haldir.key"),
      "--reason",
      "Test revocation",
      "--list",
      revocationPath,
    ]);

    try {
      await execFileAsync("node", [
        CLI_PATH,
        "verify",
        skillDir,
        "--key",
        join(tempDir, "haldir.pub"),
        "--context",
        "runtime",
        "--revocation",
        revocationPath,
      ]);
      throw new Error("Verification should have failed for revoked skill");
    } catch (error: any) {
      const result = JSON.parse(error.stdout || "{}");
      if (result.errors?.[0]?.code !== "E_REVOKED") {
        throw new Error(`Expected E_REVOKED, got ${result.errors?.[0]?.code}`);
      }
    }
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}
