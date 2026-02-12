import { describe, it, expect, vi, beforeEach } from 'vitest';
import { reviewSkill } from '../engine.js';
import type { ReviewConfig, SkillContent, ProviderConfig } from '../types.js';
import { REVIEW_QUESTIONS } from '../types.js';

vi.mock('../providers/index.js', () => ({
  callProvider: vi.fn(),
}));

import { callProvider } from '../providers/index.js';
const mockCallProvider = vi.mocked(callProvider);

const testSkill: SkillContent = {
  name: 'test',
  version: '1.0.0',
  description: 'test skill',
  files: [{ path: 'index.js', content: 'console.log("ok")' }],
};

const provider1: ProviderConfig = {
  name: 'model-a',
  type: 'openai-compatible',
  baseUrl: 'http://localhost:8000/v1',
  apiKey: 'test',
  model: 'model-a',
};

const provider2: ProviderConfig = {
  name: 'model-b',
  type: 'openai-compatible',
  baseUrl: 'http://localhost:8001/v1',
  apiKey: 'test',
  model: 'model-b',
};

function makeResponse(score: number): string {
  return JSON.stringify({
    answers: REVIEW_QUESTIONS.map(q => ({
      questionId: q.id,
      score,
      explanation: `Score ${score}`,
    })),
    reasoning: `Overall score ${score}`,
  });
}

beforeEach(() => {
  mockCallProvider.mockReset();
});

describe('reviewSkill', () => {
  it('auto-approves when both models score high', async () => {
    mockCallProvider.mockResolvedValue(makeResponse(0.98));

    const config: ReviewConfig = { providers: [provider1, provider2] };
    const result = await reviewSkill(testSkill, config);

    expect(result.status).toBe('approve');
    expect(result.decision).toBe('auto_approve');
    expect(result.score).toBeGreaterThanOrEqual(0.95);
    expect(result.reviews).toHaveLength(2);
  });

  it('auto-rejects when both models score low', async () => {
    mockCallProvider.mockResolvedValue(makeResponse(0.3));

    const config: ReviewConfig = { providers: [provider1, provider2] };
    const result = await reviewSkill(testSkill, config);

    expect(result.status).toBe('reject');
    expect(result.decision).toBe('auto_reject');
    expect(result.score).toBeLessThan(0.7);
  });

  it('sends to human review in amber zone', async () => {
    mockCallProvider.mockResolvedValue(makeResponse(0.8));

    const config: ReviewConfig = { providers: [provider1, provider2] };
    const result = await reviewSkill(testSkill, config);

    expect(result.status).toBe('amber');
    expect(result.decision).toBe('human_review');
  });

  it('escalates on disagreement', async () => {
    mockCallProvider
      .mockResolvedValueOnce(makeResponse(0.95))
      .mockResolvedValueOnce(makeResponse(0.4))
      .mockResolvedValueOnce(makeResponse(0.9));

    const escalation: ProviderConfig = {
      name: 'escalation',
      type: 'anthropic',
      baseUrl: 'https://api.anthropic.com/v1',
      apiKey: 'test',
      model: 'claude-sonnet',
    };

    const config: ReviewConfig = {
      providers: [provider1, provider2],
      escalationProvider: escalation,
    };

    const result = await reviewSkill(testSkill, config);
    expect(result.escalated).toBe(true);
    expect(result.escalationReview).toBeDefined();
  });

  it('handles provider errors gracefully', async () => {
    mockCallProvider.mockRejectedValue(new Error('API down'));

    const config: ReviewConfig = { providers: [provider1] };
    const result = await reviewSkill(testSkill, config);

    expect(result.status).toBe('amber');
    expect(result.decision).toBe('human_review');
    expect(result.reviews[0].error).toContain('API down');
  });

  it('handles parse failure', async () => {
    mockCallProvider.mockResolvedValue('not valid json at all');

    const config: ReviewConfig = { providers: [provider1] };
    const result = await reviewSkill(testSkill, config);

    expect(result.reviews[0].error).toContain('Failed to parse');
    expect(result.status).toBe('amber');
  });

  it('computes disagreement correctly', async () => {
    mockCallProvider
      .mockResolvedValueOnce(makeResponse(0.9))
      .mockResolvedValueOnce(makeResponse(0.5));

    const config: ReviewConfig = { providers: [provider1, provider2] };
    const result = await reviewSkill(testSkill, config);

    expect(result.disagreement).toBeCloseTo(0.4, 1);
  });

  it('respects custom thresholds', async () => {
    mockCallProvider.mockResolvedValue(makeResponse(0.85));

    const config: ReviewConfig = {
      providers: [provider1],
      autoApproveThreshold: 0.80,
    };
    const result = await reviewSkill(testSkill, config);

    expect(result.status).toBe('approve');
    expect(result.decision).toBe('auto_approve');
  });

  it('has duration_ms populated', async () => {
    mockCallProvider.mockResolvedValue(makeResponse(0.9));

    const config: ReviewConfig = { providers: [provider1] };
    const result = await reviewSkill(testSkill, config);

    expect(result.duration_ms).toBeGreaterThanOrEqual(0);
  });

  it('runs providers in parallel', async () => {
    let callCount = 0;
    mockCallProvider.mockImplementation(async () => {
      callCount++;
      await new Promise(r => setTimeout(r, 50));
      return makeResponse(0.9);
    });

    const config: ReviewConfig = { providers: [provider1, provider2] };
    const start = performance.now();
    await reviewSkill(testSkill, config);
    const elapsed = performance.now() - start;

    expect(callCount).toBe(2);
    expect(elapsed).toBeLessThan(200);
  });

  it('single provider works', async () => {
    mockCallProvider.mockResolvedValue(makeResponse(0.98));

    const config: ReviewConfig = { providers: [provider1] };
    const result = await reviewSkill(testSkill, config);

    expect(result.status).toBe('approve');
    expect(result.disagreement).toBe(0);
  });
});
