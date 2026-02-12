import type { ProviderConfig } from '../types.js';
import { callOpenAICompatible } from './openai-compatible.js';
import { callAnthropic } from './anthropic.js';

export async function callProvider(
  config: ProviderConfig,
  prompt: string,
  timeout: number,
): Promise<string> {
  switch (config.type) {
    case 'openai-compatible':
      return callOpenAICompatible(config, prompt, timeout);
    case 'anthropic':
      return callAnthropic(config, prompt, timeout);
    case 'custom':
      return callOpenAICompatible(config, prompt, timeout);
    default:
      throw new Error(`Unknown provider type: ${config.type}`);
  }
}
