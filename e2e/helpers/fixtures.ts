import { mkdtemp, writeFile, mkdir, readFile, unlink, symlink, link } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { rimraf } from "rimraf";

export interface TestSkill {
  path: string;
  name: string;
  cleanup: () => Promise<void>;
}

/**
 * Create a temporary test skill
 */
export async function createTestSkill(options: {
  name?: string;
  files: Record<string, string | Buffer>;
}): Promise<TestSkill> {
  const name = options.name || "test-skill";
  const skillPath = await mkdtemp(join(tmpdir(), `haldir-test-${name}-`));

  for (const [filename, content] of Object.entries(options.files)) {
    const filePath = join(skillPath, filename);
    const dir = resolve(filePath, "..");

    await mkdir(dir, { recursive: true });
    await writeFile(filePath, content);
  }

  return {
    path: skillPath,
    name,
    cleanup: async () => {
      await rimraf(skillPath);
    },
  };
}

/**
 * Create a simple test skill (SKILL.md + script)
 */
export async function createSimpleSkill(name: string = "hello-world"): Promise<TestSkill> {
  return createTestSkill({
    name,
    files: {
      "SKILL.md": `# ${name}\n\nA simple test skill for verification.\n\n## Permissions\nNone required.`,
      "skill.js": `#!/usr/bin/env node\nconsole.log("Hello from ${name}");`,
    },
  });
}

/**
 * Create a complex multi-file skill
 */
export async function createComplexSkill(): Promise<TestSkill> {
  return createTestSkill({
    name: "complex-skill",
    files: {
      "SKILL.md": "# Complex Skill\n\nMulti-file test skill.",
      "package.json": JSON.stringify({
        name: "complex-skill",
        version: "1.0.0",
        main: "index.js",
      }),
      "index.js": 'module.exports = { run: () => console.log("works") };',
      "lib/utils.js": 'exports.helper = () => true;',
      "lib/nested/deep.js": 'exports.deep = () => "nested";',
      "README.md": "# Complex Skill\n\nThis tests multi-file skills.",
      ".gitignore": "node_modules/\n.env",
    },
  });
}

/**
 * Create an MCP server format skill
 */
export async function createMCPServerSkill(): Promise<TestSkill> {
  return createTestSkill({
    name: "mcp-server",
    files: {
      "SKILL.md": "# MCP Server Skill\n\nMCP server format test.",
      "package.json": JSON.stringify({
        name: "@test/mcp-server",
        version: "1.0.0",
        type: "module",
        bin: {
          "test-mcp": "./dist/index.js",
        },
      }),
      "src/index.ts": 'import { Server } from "@modelcontextprotocol/sdk/server/index.js";\n\nconst server = new Server({ name: "test", version: "1.0.0" });',
      "tsconfig.json": JSON.stringify({
        compilerOptions: {
          target: "ES2022",
          module: "ESNext",
          moduleResolution: "bundler",
        },
      }),
    },
  });
}

/**
 * Add a file to an existing skill (for tamper testing)
 */
export async function addFileToSkill(skillPath: string, filename: string, content: string) {
  await writeFile(join(skillPath, filename), content);
}

/**
 * Modify a file in an existing skill (for tamper testing)
 */
export async function modifyFileInSkill(skillPath: string, filename: string, append: string) {
  const filePath = join(skillPath, filename);
  const current = await readFile(filePath, "utf-8");
  await writeFile(filePath, current + append);
}

/**
 * Remove a file from an existing skill
 */
export async function removeFileFromSkill(skillPath: string, filename: string) {
  await unlink(join(skillPath, filename));
}

/**
 * Create a symlink in a skill (for security testing)
 */
export async function createSymlinkInSkill(skillPath: string, linkName: string, target: string) {
  await symlink(target, join(skillPath, linkName));
}

/**
 * Create a hard link in a skill (for security testing)
 */
export async function createHardLinkInSkill(skillPath: string, linkName: string, existingFile: string) {
  await link(join(skillPath, existingFile), join(skillPath, linkName));
}

/**
 * Create a skill with too many files (for limit testing)
 */
export async function createOversizedSkill(fileCount: number): Promise<TestSkill> {
  const files: Record<string, string> = {
    "SKILL.md": "# Oversized Skill\n\nToo many files.",
  };

  for (let i = 0; i < fileCount; i++) {
    files[`file-${i}.txt`] = `File ${i}`;
  }

  return createTestSkill({
    name: "oversized",
    files,
  });
}

/**
 * Create a skill with a file that's too large (for limit testing)
 */
export async function createLargeFileSkill(sizeInMB: number): Promise<TestSkill> {
  const largeContent = Buffer.alloc(sizeInMB * 1024 * 1024, "x");

  return createTestSkill({
    name: "large-file",
    files: {
      "SKILL.md": "# Large File Skill",
      "large.bin": largeContent,
    },
  });
}
