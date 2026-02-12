import type { ProviderConfig } from '../types.js';

export interface ChatCompletion {
  choices: { message: { content: string } }[];
}

export async function callOpenAICompatible(
  config: ProviderConfig,
  prompt: string,
  timeout: number,
): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(`${config.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.apiKey}`,
      },
      body: JSON.stringify({
        model: config.model,
        messages: [{ role: 'user', content: prompt }],
        max_tokens: config.maxTokens ?? 2000,
        temperature: config.temperature ?? 0.1,
      }),
      signal: controller.signal,
    });

    clearTimeout(timer);

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Provider ${config.name} returned ${response.status}: ${text.slice(0, 200)}`);
    }

    const data = await response.json() as ChatCompletion;
    return data.choices?.[0]?.message?.content ?? '';
  } catch (err) {
    clearTimeout(timer);
    if (err instanceof Error && err.name === 'AbortError') {
      throw new Error(`Provider ${config.name} timed out after ${timeout}ms`);
    }
    throw err;
  }
}
