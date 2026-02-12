import { describe, test, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createSimpleSkill } from "../helpers/fixtures";
import {
  generateKeypair,
  signSkill,
  verifySkill,
  createRevocationList,
} from "../helpers/cli";

describe("Revocation - Install and Runtime Contexts", () => {
  let tempDir: string;
  let keypair: { privateKey: string; publicKey: string; keyId: string };

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "haldir-revocation-"));
    keypair = await generateKeypair(tempDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  test("reject revoked skill in install context (fail-closed)", async () => {
    const skill = await createSimpleSkill("revoked-skill");
    await signSkill(skill.path, keypair.privateKey);

    // Create revocation list
    const revocationPath = join(tempDir, "revocations.json");
    await createRevocationList(
      [{ skillId: "revoked-skill@1.0.0", reason: "Security vulnerability" }],
      keypair.privateKey,
      revocationPath
    );

    const verifyResult = await verifySkill(skill.path, keypair.publicKey, {
      context: "install",
      revocation: revocationPath,
    });

    expect(verifyResult.exitCode).not.toBe(0);
    expect(verifyResult.json?.error?.code).toBe("E_REVOKED");
    expect(verifyResult.json?.trustLevel).toBe("none");

    await skill.cleanup();
  });

  test("runtime context with no revocation list (fail-open)", async () => {
    const skill = await createSimpleSkill();
    await signSkill(skill.path, keypair.privateKey);

    // Verify in runtime context without revocation list
    const verifyResult = await verifySkill(skill.path, keypair.publicKey, {
      context: "runtime",
    });

    // Should succeed (fail-open)
    expect(verifyResult.exitCode).toBe(0);
    expect(verifyResult.json?.trustLevel).toBe("full");

    await skill.cleanup();
  });

  test("runtime context rejects revoked skill", async () => {
    const skill = await createSimpleSkill("runtime-revoked");
    await signSkill(skill.path, keypair.privateKey);

    const revocationPath = join(tempDir, "runtime-revocations.json");
    await createRevocationList(
      [{ skillId: "runtime-revoked@1.0.0", reason: "Found malware" }],
      keypair.privateKey,
      revocationPath
    );

    const verifyResult = await verifySkill(skill.path, keypair.publicKey, {
      context: "runtime",
      revocation: revocationPath,
    });

    expect(verifyResult.exitCode).not.toBe(0);
    expect(verifyResult.json?.error?.code).toBe("E_REVOKED");

    await skill.cleanup();
  });

  test("reject forged revocation list (unsigned)", async () => {
    const skill = await createSimpleSkill();
    await signSkill(skill.path, keypair.privateKey);

    // Create forged revocation list (not signed)
    const forgedPath = join(tempDir, "forged.json");
    await writeFile(
      forgedPath,
      JSON.stringify({
        version: "1.0.0",
        revoked_skills: [],
        issued_at: new Date().toISOString(),
      })
    );

    const verifyResult = await verifySkill(skill.path, keypair.publicKey, {
      context: "install",
      revocation: forgedPath,
    });

    // Should fail due to invalid revocation list
    expect(verifyResult.exitCode).not.toBe(0);

    await skill.cleanup();
  });

  test("handle expired revocation list gracefully", async () => {
    const skill = await createSimpleSkill();
    await signSkill(skill.path, keypair.privateKey);

    // Create revocation list with past expiry
    const expiredPath = join(tempDir, "expired.json");
    const pastDate = new Date();
    pastDate.setFullYear(pastDate.getFullYear() - 1);

    await writeFile(
      expiredPath,
      JSON.stringify({
        version: "1.0.0",
        revoked_skills: [],
        issued_at: pastDate.toISOString(),
        expires_at: pastDate.toISOString(),
      })
    );

    const verifyResult = await verifySkill(skill.path, keypair.publicKey, {
      context: "install",
      revocation: expiredPath,
    });

    // Expired list should be ignored
    expect(verifyResult.json?.warnings).toBeDefined();

    await skill.cleanup();
  });

  test("multiple revocations in single list", async () => {
    const skill1 = await createSimpleSkill("skill-1");
    const skill2 = await createSimpleSkill("skill-2");
    const skill3 = await createSimpleSkill("skill-3");

    await signSkill(skill1.path, keypair.privateKey);
    await signSkill(skill2.path, keypair.privateKey);
    await signSkill(skill3.path, keypair.privateKey);

    // Revoke skills 1 and 3
    const revocationPath = join(tempDir, "multi-revocations.json");
    await createRevocationList(
      [
        { skillId: "skill-1@1.0.0", reason: "Reason 1" },
        { skillId: "skill-3@1.0.0", reason: "Reason 3" },
      ],
      keypair.privateKey,
      revocationPath
    );

    // skill-1: revoked
    const verify1 = await verifySkill(skill1.path, keypair.publicKey, {
      context: "install",
      revocation: revocationPath,
    });
    expect(verify1.json?.error?.code).toBe("E_REVOKED");

    // skill-2: not revoked
    const verify2 = await verifySkill(skill2.path, keypair.publicKey, {
      context: "install",
      revocation: revocationPath,
    });
    expect(verify2.exitCode).toBe(0);

    // skill-3: revoked
    const verify3 = await verifySkill(skill3.path, keypair.publicKey, {
      context: "install",
      revocation: revocationPath,
    });
    expect(verify3.json?.error?.code).toBe("E_REVOKED");

    await skill1.cleanup();
    await skill2.cleanup();
    await skill3.cleanup();
  });
});
