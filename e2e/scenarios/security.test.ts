import { describe, test, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createSimpleSkill,
  addFileToSkill,
  modifyFileInSkill,
  removeFileFromSkill,
  createSymlinkInSkill,
  createHardLinkInSkill,
  createOversizedSkill,
  createLargeFileSkill,
} from "../helpers/fixtures";
import {
  generateKeypair,
  signSkill,
  verifySkill,
} from "../helpers/cli";

describe("Security - Tamper Detection", () => {
  let tempDir: string;
  let keypair: { privateKey: string; publicKey: string; keyId: string };

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "haldir-security-"));
    keypair = await generateKeypair(tempDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  test("detect added file (not in allowlist)", async () => {
    const skill = await createSimpleSkill();
    await signSkill(skill.path, keypair.privateKey);

    // Tamper: add extra file
    await addFileToSkill(skill.path, "backdoor.js", "console.log('malicious');");

    const verifyResult = await verifySkill(skill.path, keypair.publicKey, {
      context: "install",
    });

    expect(verifyResult.exitCode).not.toBe(0);
    expect(verifyResult.json?.error?.code).toBe("E_EXTRA_FILES");
    expect(verifyResult.json?.trustLevel).toBe("none");

    await skill.cleanup();
  });

  test("detect modified file (hash mismatch)", async () => {
    const skill = await createSimpleSkill();
    await signSkill(skill.path, keypair.privateKey);

    // Tamper: modify existing file
    await modifyFileInSkill(skill.path, "skill.js", "\n// tampered");

    const verifyResult = await verifySkill(skill.path, keypair.publicKey, {
      context: "install",
    });

    expect(verifyResult.exitCode).not.toBe(0);
    expect(verifyResult.json?.error?.code).toBe("E_INTEGRITY_MISMATCH");
    expect(verifyResult.json?.trustLevel).toBe("none");

    await skill.cleanup();
  });

  test("detect removed file (missing from disk)", async () => {
    const skill = await createSimpleSkill();
    await signSkill(skill.path, keypair.privateKey);

    // Tamper: remove file
    await removeFileFromSkill(skill.path, "skill.js");

    const verifyResult = await verifySkill(skill.path, keypair.publicKey, {
      context: "install",
    });

    expect(verifyResult.exitCode).not.toBe(0);
    expect(verifyResult.json?.error?.code).toBe("E_INTEGRITY_MISMATCH");
    expect(verifyResult.json?.trustLevel).toBe("none");

    await skill.cleanup();
  });

  test("detect symlink attack", async () => {
    const skill = await createSimpleSkill();

    // Attack: add symlink before signing
    await createSymlinkInSkill(skill.path, "evil-link", "/etc/passwd");

    const signResult = await signSkill(skill.path, keypair.privateKey);

    expect(signResult.exitCode).not.toBe(0);
    expect(signResult.stderr).toContain("symlink");

    await skill.cleanup();
  });

  test("detect hard link attack", async () => {
    const skill = await createSimpleSkill();

    // Attack: add hard link before signing
    await createHardLinkInSkill(skill.path, "evil-hardlink", "skill.js");

    const signResult = await signSkill(skill.path, keypair.privateKey);

    expect(signResult.exitCode).not.toBe(0);
    expect(signResult.stderr).toContain("hard link");

    await skill.cleanup();
  });

  test("reject wrong public key", async () => {
    const skill = await createSimpleSkill();
    await signSkill(skill.path, keypair.privateKey);

    // Generate different keypair
    const wrongKeypair = await generateKeypair(tempDir + "-wrong");

    const verifyResult = await verifySkill(skill.path, wrongKeypair.publicKey, {
      context: "install",
    });

    expect(verifyResult.exitCode).not.toBe(0);
    expect(verifyResult.json?.error?.code).toBe("E_BAD_SIGNATURE");
    expect(verifyResult.json?.trustLevel).toBe("none");

    await skill.cleanup();
    await rm(tempDir + "-wrong", { recursive: true, force: true });
  });

  test("reject skill with too many files (>10K)", async () => {
    const skill = await createOversizedSkill(10001);

    const signResult = await signSkill(skill.path, keypair.privateKey);

    expect(signResult.exitCode).not.toBe(0);
    expect(signResult.stderr).toContain("too many files");

    await skill.cleanup();
  });

  test("reject skill with file too large (>100MB)", async () => {
    const skill = await createLargeFileSkill(101);

    const signResult = await signSkill(skill.path, keypair.privateKey);

    expect(signResult.exitCode).not.toBe(0);
    expect(signResult.stderr).toContain("too large");

    await skill.cleanup();
  });

  test("verify fails if attestation tampered", async () => {
    const skill = await createSimpleSkill();
    await signSkill(skill.path, keypair.privateKey);

    // Tamper: modify attestation.json
    const attestationPath = join(skill.path, ".vault", "attestation.json");
    await modifyFileInSkill(skill.path, ".vault/attestation.json", "\n");

    const verifyResult = await verifySkill(skill.path, keypair.publicKey, {
      context: "install",
    });

    expect(verifyResult.exitCode).not.toBe(0);
    expect(verifyResult.json?.trustLevel).toBe("none");

    await skill.cleanup();
  });
});
