import { Command } from 'commander';
import { keygenCommand } from './commands/keygen.js';
import { signCommand } from './commands/sign.js';
import { verifyCommand } from './commands/verify.js';
import { inspectCommand } from './commands/inspect.js';
import { cosignCommand } from './commands/cosign.js';
import { revokeCommand } from './commands/revoke.js';
import { scanCommand } from './commands/scan.js';
import { auditCommand } from './commands/audit.js';
import { sandboxCommand } from './commands/sandbox.js';
import { reviewCommand } from './commands/review.js';
import { enforceCommand } from './commands/enforce.js';
import { runTestSuite } from './commands/test.js';

function collect(val: string, acc: string[]): string[] {
  acc.push(val);
  return acc;
}

const program = new Command();

program
  .name('haldir')
  .description('Haldir — secure agent skills registry')
  .version('0.1.0');

program
  .command('keygen')
  .description('Generate Ed25519 keypair')
  .option('--output <dir>', 'Output directory for generated keys (default: current directory)')
  .action(async (opts) => {
    try {
      await keygenCommand(opts);
    } catch (e) {
      console.error(e instanceof Error ? e.message : e);
      process.exit(2);
    }
  });

program
  .command('sign <dir>')
  .description('Create .vault/ envelope for a skill directory')
  .option('--key <path>', 'Path to Ed25519 private key')
  .option('--keyless', 'Use Sigstore keyless signing (OIDC-based)')
  .option('--identity-token <token>', 'OIDC identity token for Sigstore signing')
  .option('--name <name>', 'Skill name')
  .option('--skill-version <version>', 'Skill version')
  .option('--type <type>', 'Skill type (skill.md or mcp)')
  .action(async (dir: string, opts) => {
    try {
      await signCommand(dir, opts);
    } catch (e) {
      console.error(e instanceof Error ? e.message : e);
      process.exit(1);
    }
  });

program
  .command('verify <dir>')
  .description('Verify .vault/ envelope (auto-detects Ed25519 or Sigstore)')
  .option('--key <path>', 'Path to Ed25519 public key')
  .option('--keyless', 'Force Sigstore verification mode')
  .option('--trusted-identity <issuer=subject>', 'Trusted signer identity for Sigstore (repeatable)', collect, [])
  .option('--revocation <path>', 'Path to revocation list')
  .option('--revocation-key <path>', 'Path to Ed25519 public key for revocation list verification')
  .option('--context <context>', 'Verification context: install or runtime', 'install')
  .option('--skip-hardlink-check', 'Skip hard link check (runtime only)')
  .action(async (dir: string, opts) => {
    try {
      await verifyCommand(dir, opts);
    } catch (e) {
      console.error(e instanceof Error ? e.message : e);
      process.exit(2);
    }
  });

program
  .command('inspect <dir>')
  .description('Display attestation, permissions, and integrity (no verification)')
  .action(async (dir: string) => {
    try {
      await inspectCommand(dir);
    } catch (e) {
      console.error(e instanceof Error ? e.message : e);
      process.exit(2);
    }
  });

program
  .command('cosign <dir>')
  .description('Add a co-signature to an existing .vault/ envelope (dual-sign)')
  .requiredOption('--key <path>', 'Path to co-signer Ed25519 private key')
  .option('--trusted-key <path>', 'Trusted public key to verify existing signatures (repeatable)', collect, [])
  .action(async (dir: string, opts) => {
    try {
      await cosignCommand(dir, opts);
    } catch (e) {
      console.error(e instanceof Error ? e.message : e);
      process.exit(1);
    }
  });

program
  .command('revoke <name@version>')
  .description('Add entry to revocation list')
  .requiredOption('--key <path>', 'Path to private key')
  .requiredOption('--list <path>', 'Path to revocation list file')
  .requiredOption('--reason <text>', 'Reason for revocation')
  .option('--severity <level>', 'Severity level', 'high')
  .action(async (nameAtVersion: string, opts) => {
    try {
      await revokeCommand(nameAtVersion, opts);
    } catch (e) {
      console.error(e instanceof Error ? e.message : e);
      process.exit(2);
    }
  });

program
  .command('scan <dir>')
  .description('Scan skill directory for security threats (static analysis)')
  .option('--severity <level>', 'Minimum severity to report (critical|high|medium|low)', 'low')
  .option('--json', 'Output as JSON')
  .option('--strict', 'Exit code 1 on any finding (not just critical)')
  .action(async (dir: string, opts) => {
    try {
      await scanCommand(dir, opts);
    } catch (e) {
      console.error(e instanceof Error ? e.message : e);
      process.exit(2);
    }
  });

program
  .command('audit <dir>')
  .description('Audit skill dependencies (pinning, lockfiles, CVEs, depth)')
  .option('--json', 'Output as JSON')
  .option('--type <type>', 'Force skill type (skill.md or mcp)')
  .option('--no-cve', 'Skip CVE advisory lookup')
  .action(async (dir: string, opts) => {
    try {
      await auditCommand(dir, opts);
    } catch (e) {
      console.error(e instanceof Error ? e.message : e);
      process.exit(2);
    }
  });

program
  .command('sandbox <dir>')
  .description('Run skill in sandbox and monitor behavior (Layer 3)')
  .option('--json', 'Output as JSON')
  .option('--timeout <ms>', 'Execution timeout in milliseconds', '30000')
  .option('--entrypoint <cmd>', 'Override entrypoint command')
  .action(async (dir: string, opts) => {
    try {
      await sandboxCommand(dir, opts);
    } catch (e) {
      console.error(e instanceof Error ? e.message : e);
      process.exit(2);
    }
  });

program
  .command('review <dir>')
  .description('LLM semantic audit of skill (Layer 4 — requires provider config)')
  .option('--json', 'Output as JSON')
  .option('--provider <config>', 'Provider config "name:type:url:key:model" (repeatable)', collect, [])
  .option('--timeout <ms>', 'Per-provider timeout in milliseconds', '30000')
  .option('--approve-threshold <n>', 'Auto-approve score threshold (0.0-1.0)', '0.95')
  .option('--reject-threshold <n>', 'Auto-reject score threshold (0.0-1.0)', '0.70')
  .action(async (dir: string, opts) => {
    try {
      await reviewCommand(dir, opts);
    } catch (e) {
      console.error(e instanceof Error ? e.message : e);
      process.exit(2);
    }
  });

program
  .command('enforce <dir>')
  .description('Run skill with runtime permission enforcement (Phase 2D)')
  .option('--json', 'Output as JSON')
  .option('--backend <type>', 'Enforcement backend: node-permissions, darwin-sandbox, linux-landlock, auto', 'auto')
  .option('--timeout <ms>', 'Execution timeout in milliseconds')
  .option('--entrypoint <file>', 'Override entrypoint file')
  .action(async (dir: string, opts) => {
    try {
      await enforceCommand(dir, opts);
    } catch (e) {
      console.error(e instanceof Error ? e.message : e);
      process.exit(2);
    }
  });

program
  .command('test')
  .description('Run built-in end-to-end test suite')
  .action(async () => {
    try {
      await runTestSuite();
    } catch (e) {
      console.error(e instanceof Error ? e.message : e);
      process.exit(2);
    }
  });

program.parse();
