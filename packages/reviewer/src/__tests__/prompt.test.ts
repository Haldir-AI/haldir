import { describe, it, expect } from 'vitest';
import { buildReviewPrompt, parseReviewResponse, computeWeightedScore } from '../prompt.js';
import { REVIEW_QUESTIONS } from '../types.js';
import type { SkillContent } from '../types.js';

const testSkill: SkillContent = {
  name: 'test-skill',
  version: '1.0.0',
  description: 'A test skill for unit testing',
  files: [
    { path: 'index.js', content: 'console.log("hello");' },
    { path: 'SKILL.md', content: '# Test Skill\nDoes testing.' },
  ],
  permissions: { network: false, filesystem: { read: ['./data'] } },
};

describe('buildReviewPrompt', () => {
  it('includes skill metadata', () => {
    const prompt = buildReviewPrompt(testSkill);
    expect(prompt).toContain('test-skill');
    expect(prompt).toContain('1.0.0');
    expect(prompt).toContain('A test skill for unit testing');
  });

  it('includes file contents', () => {
    const prompt = buildReviewPrompt(testSkill);
    expect(prompt).toContain('index.js');
    expect(prompt).toContain('console.log("hello")');
  });

  it('includes permissions', () => {
    const prompt = buildReviewPrompt(testSkill);
    expect(prompt).toContain('"network": false');
  });

  it('includes all review questions', () => {
    const prompt = buildReviewPrompt(testSkill);
    for (const q of REVIEW_QUESTIONS) {
      expect(prompt).toContain(q.id);
    }
  });

  it('handles skill without permissions', () => {
    const skill = { ...testSkill, permissions: undefined };
    const prompt = buildReviewPrompt(skill);
    expect(prompt).toContain('None declared');
  });

  it('truncates large files', () => {
    const skill = {
      ...testSkill,
      files: [{ path: 'big.js', content: 'x'.repeat(10000) }],
    };
    const prompt = buildReviewPrompt(skill);
    expect(prompt.length).toBeLessThan(15000);
  });
});

describe('parseReviewResponse', () => {
  it('parses valid JSON response', () => {
    const raw = JSON.stringify({
      answers: [
        { questionId: 'description_match', score: 0.9, explanation: 'Matches well' },
        { questionId: 'hidden_directives', score: 1.0, explanation: 'None found' },
      ],
      reasoning: 'Looks safe overall',
    });
    const result = parseReviewResponse(raw);
    expect(result).not.toBeNull();
    expect(result!.answers).toHaveLength(2);
    expect(result!.answers[0].score).toBe(0.9);
    expect(result!.reasoning).toBe('Looks safe overall');
  });

  it('strips markdown fences', () => {
    const raw = '```json\n{"answers":[{"questionId":"a","score":0.5,"explanation":"ok"}],"reasoning":"fine"}\n```';
    const result = parseReviewResponse(raw);
    expect(result).not.toBeNull();
    expect(result!.answers[0].score).toBe(0.5);
  });

  it('clamps scores to 0-1', () => {
    const raw = JSON.stringify({
      answers: [
        { questionId: 'a', score: 1.5, explanation: 'over' },
        { questionId: 'b', score: -0.5, explanation: 'under' },
      ],
      reasoning: '',
    });
    const result = parseReviewResponse(raw);
    expect(result!.answers[0].score).toBe(1.0);
    expect(result!.answers[1].score).toBe(0.0);
  });

  it('returns null for invalid JSON', () => {
    expect(parseReviewResponse('not json')).toBeNull();
  });

  it('returns null for missing answers array', () => {
    expect(parseReviewResponse('{"reasoning":"ok"}')).toBeNull();
  });

  it('handles NaN scores', () => {
    const raw = JSON.stringify({
      answers: [{ questionId: 'a', score: 'bad', explanation: 'ok' }],
      reasoning: '',
    });
    const result = parseReviewResponse(raw);
    expect(result!.answers[0].score).toBe(0);
  });
});

describe('computeWeightedScore', () => {
  it('computes weighted average', () => {
    const answers = REVIEW_QUESTIONS.map(q => ({
      questionId: q.id,
      score: 1.0,
    }));
    expect(computeWeightedScore(answers)).toBe(1.0);
  });

  it('returns 0 for all zero scores', () => {
    const answers = REVIEW_QUESTIONS.map(q => ({
      questionId: q.id,
      score: 0.0,
    }));
    expect(computeWeightedScore(answers)).toBe(0.0);
  });

  it('handles missing answers gracefully', () => {
    const answers = [{ questionId: 'description_match', score: 0.8 }];
    const score = computeWeightedScore(answers);
    expect(score).toBeGreaterThan(0);
    expect(score).toBeLessThanOrEqual(1);
  });

  it('returns 0 for empty answers', () => {
    expect(computeWeightedScore([])).toBe(0);
  });

  it('weights high-weight questions more', () => {
    // exfil_risk (0.25) vs code_quality (0.10) — scoring only one at 1.0
    const onlyExfil = REVIEW_QUESTIONS.map(q => ({
      questionId: q.id,
      score: q.id === 'exfil_risk' ? 1.0 : 0.0,
    }));
    const onlyQuality = REVIEW_QUESTIONS.map(q => ({
      questionId: q.id,
      score: q.id === 'code_quality' ? 1.0 : 0.0,
    }));
    expect(computeWeightedScore(onlyExfil)).toBeGreaterThan(computeWeightedScore(onlyQuality));
  });
});
