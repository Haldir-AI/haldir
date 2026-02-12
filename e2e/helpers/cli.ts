import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { resolve } from "node:path";

const execFileAsync = promisify(execFile);

const CLI_PATH = resolve(__dirname, "../../packages/cli/dist/index.js");

export interface CLIResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  json?: any;
}

/**
 * Run haldir CLI command and return result
 */
export async function runCLI(...args: string[]): Promise<CLIResult> {
  try {
    const { stdout, stderr } = await execFileAsync("node", [CLI_PATH, ...args]);

    let json;
    try {
      json = JSON.parse(stdout);
    } catch {
      // Not JSON output, that's fine
    }

    return {
      exitCode: 0,
      stdout,
      stderr,
      json,
    };
  } catch (error: any) {
    let json;
    try {
      json = JSON.parse(error.stdout || "{}");
    } catch {
      // Not JSON output
    }

    return {
      exitCode: error.code || 1,
      stdout: error.stdout || "",
      stderr: error.stderr || "",
      json,
    };
  }
}

/**
 * Run keygen and return keypair paths
 */
export async function generateKeypair(outputDir: string) {
  await runCLI("keygen", "--output", outputDir);

  return {
    privateKey: resolve(outputDir, "haldir.key"),
    publicKey: resolve(outputDir, "haldir.pub"),
    keyId: resolve(outputDir, "haldir.keyid"),
  };
}

/**
 * Sign a skill directory
 */
export async function signSkill(skillPath: string, privateKeyPath: string) {
  return runCLI("sign", skillPath, "--key", privateKeyPath);
}

/**
 * Verify a skill directory
 */
export async function verifySkill(
  skillPath: string,
  publicKeyPath: string,
  options: {
    context?: "install" | "runtime";
    revocation?: string;
  } = {}
) {
  const args = ["verify", skillPath, "--key", publicKeyPath];

  if (options.context) {
    args.push("--context", options.context);
  }

  if (options.revocation) {
    args.push("--revocation", options.revocation);
  }

  return runCLI(...args);
}

/**
 * Inspect a skill's attestation
 */
export async function inspectSkill(skillPath: string) {
  return runCLI("inspect", skillPath);
}

/**
 * Create a revocation list
 */
export async function createRevocationList(
  entries: Array<{ skillId: string; reason: string }>,
  privateKeyPath: string,
  outputPath: string
) {
  for (const entry of entries) {
    await runCLI(
      "revoke",
      entry.skillId,
      "--key", privateKeyPath,
      "--reason", entry.reason,
      "--list", outputPath
    );
  }
}
