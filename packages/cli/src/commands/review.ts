import { reviewSkill, collectSkillContent } from '@haldir/reviewer';
import type { ReviewConfig, ReviewResult, ProviderConfig } from '@haldir/reviewer';

interface ReviewCommandOptions {
  json?: boolean;
  provider?: string[];
  timeout?: string;
  approveThreshold?: string;
  rejectThreshold?: string;
}

export async function reviewCommand(dir: string, opts: ReviewCommandOptions): Promise<void> {
  const skill = await collectSkillContent(dir);
  const providers = parseProviders(opts.provider ?? []);

  if (providers.length === 0) {
    console.error('No providers configured. Use --provider "name:type:url:key:model" (repeatable)');
    console.error('Example: --provider "deepseek:openai-compatible:https://api.deepseek.com/v1:sk-xxx:deepseek-chat"');
    process.exit(2);
  }

  const config: ReviewConfig = {
    providers,
    timeout: opts.timeout ? parseInt(opts.timeout, 10) : undefined,
    autoApproveThreshold: opts.approveThreshold ? parseFloat(opts.approveThreshold) : undefined,
    autoRejectThreshold: opts.rejectThreshold ? parseFloat(opts.rejectThreshold) : undefined,
  };

  const result = await reviewSkill(skill, config);

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printHumanReadable(result);
  }

  if (result.status === 'reject') process.exit(1);
}

function parseProviders(raw: string[]): ProviderConfig[] {
  return raw.map(s => {
    const parts = s.split(':');
    if (parts.length < 5) {
      console.error(`Invalid provider format: "${s}". Expected "name:type:url:key:model"`);
      process.exit(2);
    }
    const name = parts[0];
    const type = parts[1];
    const model = parts[parts.length - 1];
    const apiKey = parts[parts.length - 2];
    const baseUrl = parts.slice(2, parts.length - 2).join(':');
    if (!name || !type || !baseUrl || !apiKey || !model) {
      console.error(`Invalid provider format: "${s}". Expected "name:type:url:key:model"`);
      process.exit(2);
    }
    return {
      name,
      type: type as ProviderConfig['type'],
      baseUrl,
      apiKey,
      model,
    };
  });
}

const STATUS_COLORS: Record<string, string> = {
  approve: '\x1b[32m',
  reject: '\x1b[31m',
  amber: '\x1b[33m',
};
const RESET = '\x1b[0m';

function printHumanReadable(result: ReviewResult): void {
  const color = STATUS_COLORS[result.status] ?? '';
  console.log(`\nReview: score=${result.score}, disagreement=${result.disagreement}, ${result.duration_ms}ms`);

  for (const r of result.reviews) {
    const status = r.error ? `ERROR: ${r.error}` : `score=${r.score}`;
    console.log(`  ${r.provider} (${r.model}): ${status} [${r.duration_ms}ms]`);
    if (r.reasoning) console.log(`    ${r.reasoning.slice(0, 150)}`);
  }

  if (result.escalated && result.escalationReview) {
    console.log(`  ESCALATED → ${result.escalationReview.provider}: score=${result.escalationReview.score}`);
  }

  console.log(`\nDecision: ${result.decision}`);
  console.log(`Status: ${color}${result.status.toUpperCase()}${RESET}\n`);
}
