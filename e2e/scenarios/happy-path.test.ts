import { describe, test, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createSimpleSkill,
  createComplexSkill,
  createMCPServerSkill,
} from "../helpers/fixtures";
import {
  generateKeypair,
  signSkill,
  verifySkill,
  inspectSkill,
} from "../helpers/cli";

describe("Happy Path - Valid Skills", () => {
  let tempDir: string;
  let keypair: { privateKey: string; publicKey: string; keyId: string };

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "haldir-happy-"));
    keypair = await generateKeypair(tempDir);
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  test("sign and verify simple skill", async () => {
    const skill = await createSimpleSkill();

    const signResult = await signSkill(skill.path, keypair.privateKey);
    expect(signResult.exitCode).toBe(0);
    expect(signResult.stdout).toContain("✓");

    const verifyResult = await verifySkill(skill.path, keypair.publicKey, {
      context: "install",
    });
    expect(verifyResult.exitCode).toBe(0);
    expect(verifyResult.json?.trustLevel).toBe("full");
    expect(verifyResult.json?.checks?.passed).toBeGreaterThanOrEqual(25);

    await skill.cleanup();
  });

  test("sign and verify complex multi-file skill", async () => {
    const skill = await createComplexSkill();

    const signResult = await signSkill(skill.path, keypair.privateKey);
    expect(signResult.exitCode).toBe(0);

    const verifyResult = await verifySkill(skill.path, keypair.publicKey, {
      context: "install",
    });
    expect(verifyResult.exitCode).toBe(0);
    expect(verifyResult.json?.trustLevel).toBe("full");

    await skill.cleanup();
  });

  test("sign and verify MCP server format", async () => {
    const skill = await createMCPServerSkill();

    const signResult = await signSkill(skill.path, keypair.privateKey);
    expect(signResult.exitCode).toBe(0);

    const verifyResult = await verifySkill(skill.path, keypair.publicKey, {
      context: "install",
    });
    expect(verifyResult.exitCode).toBe(0);
    expect(verifyResult.json?.trustLevel).toBe("full");

    await skill.cleanup();
  });

  test("inspect signed skill", async () => {
    const skill = await createSimpleSkill();
    await signSkill(skill.path, keypair.privateKey);

    const inspectResult = await inspectSkill(skill.path);
    expect(inspectResult.exitCode).toBe(0);
    expect(inspectResult.json?.attestation).toBeDefined();
    expect(inspectResult.json?.attestation.skill_name).toBeDefined();
    expect(inspectResult.json?.attestation.integrity_hash).toBeDefined();

    await skill.cleanup();
  });

  test("verify in runtime context (no revocation list)", async () => {
    const skill = await createSimpleSkill();
    await signSkill(skill.path, keypair.privateKey);

    const verifyResult = await verifySkill(skill.path, keypair.publicKey, {
      context: "runtime",
    });
    expect(verifyResult.exitCode).toBe(0);
    expect(verifyResult.json?.trustLevel).toBe("full");

    await skill.cleanup();
  });

  test("sign skill multiple times (idempotent)", async () => {
    const skill = await createSimpleSkill();

    const sign1 = await signSkill(skill.path, keypair.privateKey);
    expect(sign1.exitCode).toBe(0);

    const sign2 = await signSkill(skill.path, keypair.privateKey);
    expect(sign2.exitCode).toBe(0);

    const verifyResult = await verifySkill(skill.path, keypair.publicKey, {
      context: "install",
    });
    expect(verifyResult.exitCode).toBe(0);

    await skill.cleanup();
  });
});
