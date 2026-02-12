import type { ProviderConfig } from '../types.js';

export interface AnthropicMessage {
  content: { type: string; text: string }[];
}

export async function callAnthropic(
  config: ProviderConfig,
  prompt: string,
  timeout: number,
): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(`${config.baseUrl}/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': config.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: config.model,
        max_tokens: config.maxTokens ?? 2000,
        temperature: config.temperature ?? 0.1,
        messages: [{ role: 'user', content: prompt }],
      }),
      signal: controller.signal,
    });

    clearTimeout(timer);

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Anthropic returned ${response.status}: ${text.slice(0, 200)}`);
    }

    const data = await response.json() as AnthropicMessage;
    const textBlock = data.content?.find(b => b.type === 'text');
    return textBlock?.text ?? '';
  } catch (err) {
    clearTimeout(timer);
    if (err instanceof Error && err.name === 'AbortError') {
      throw new Error(`Anthropic timed out after ${timeout}ms`);
    }
    throw err;
  }
}
