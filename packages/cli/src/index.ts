import { Command } from 'commander';
import { keygenCommand } from './commands/keygen.js';
import { signCommand } from './commands/sign.js';
import { verifyCommand } from './commands/verify.js';
import { inspectCommand } from './commands/inspect.js';
import { revokeCommand } from './commands/revoke.js';

const program = new Command();

program
  .name('haldir')
  .description('Haldir — secure agent skills registry')
  .version('0.1.0');

program
  .command('keygen')
  .description('Generate Ed25519 keypair')
  .action(async () => {
    try {
      await keygenCommand();
    } catch (e) {
      console.error(e instanceof Error ? e.message : e);
      process.exit(2);
    }
  });

program
  .command('sign <dir>')
  .description('Create .vault/ envelope for a skill directory')
  .requiredOption('--key <path>', 'Path to private key')
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
  .description('Verify .vault/ envelope')
  .requiredOption('--key <path>', 'Path to public key')
  .option('--revocation <path>', 'Path to revocation list')
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

program.parse();
