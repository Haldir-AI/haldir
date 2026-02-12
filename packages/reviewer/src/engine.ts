import type {
  ReviewConfig, ReviewResult, ProviderReview, SkillContent,
  ReviewStatus, ReviewDecision,
} from './types.js';
import {
  DEFAULT_AUTO_APPROVE, DEFAULT_AUTO_REJECT,
  DEFAULT_DISAGREEMENT, DEFAULT_TIMEOUT,
} from './types.js';
import { buildReviewPrompt, parseReviewResponse, computeWeightedScore } from './prompt.js';
import { callProvider } from './providers/index.js';

export async function reviewSkill(
  skill: SkillContent,
  config: ReviewConfig,
): Promise<ReviewResult> {
  const start = performance.now();
  const timeout = config.timeout ?? DEFAULT_TIMEOUT;

  const prompt = buildReviewPrompt(skill);
  const reviews = await runParallelReviews(prompt, config.providers, timeout);

  const validReviews = reviews.filter(r => !r.error);

  if (validReviews.length === 0) {
    return {
      status: 'amber',
      decision: 'human_review',
      score: 0,
      reviews,
      disagreement: 0,
      duration_ms: Math.round(performance.now() - start),
    };
  }

  const avgScore = validReviews.reduce((s, r) => s + r.score, 0) / validReviews.length;
  const disagreement = computeDisagreement(validReviews);

  const autoApprove = config.autoApproveThreshold ?? DEFAULT_AUTO_APPROVE;
  const autoReject = config.autoRejectThreshold ?? DEFAULT_AUTO_REJECT;
  const disagreeThreshold = config.disagreementThreshold ?? DEFAULT_DISAGREEMENT;

  let status: ReviewStatus;
  let decision: ReviewDecision;
  let escalated = false;
  let escalationReview: ProviderReview | undefined;

  if (disagreement > disagreeThreshold && config.escalationProvider) {
    escalated = true;
    escalationReview = await runSingleReview(prompt, config.escalationProvider, timeout);
    const escalatedScore = escalationReview.error ? avgScore : escalationReview.score;
    const finalScore = (avgScore + escalatedScore) / 2;

    if (finalScore >= autoApprove) {
      status = 'approve';
      decision = 'escalate';
    } else if (finalScore < autoReject) {
      status = 'reject';
      decision = 'escalate';
    } else {
      status = 'amber';
      decision = 'human_review';
    }
  } else if (avgScore >= autoApprove) {
    status = 'approve';
    decision = 'auto_approve';
  } else if (avgScore < autoReject) {
    status = 'reject';
    decision = 'auto_reject';
  } else {
    status = 'amber';
    decision = 'human_review';
  }

  return {
    status,
    decision,
    score: Math.round(avgScore * 1000) / 1000,
    reviews,
    disagreement: Math.round(disagreement * 1000) / 1000,
    duration_ms: Math.round(performance.now() - start),
    escalated,
    escalationReview,
  };
}

async function runParallelReviews(
  prompt: string,
  providers: ReviewConfig['providers'],
  timeout: number,
): Promise<ProviderReview[]> {
  const promises = providers.map(p => runSingleReview(prompt, p, timeout));
  return Promise.all(promises);
}

async function runSingleReview(
  prompt: string,
  provider: ReviewConfig['providers'][number],
  timeout: number,
): Promise<ProviderReview> {
  const start = performance.now();

  try {
    const raw = await callProvider(provider, prompt, timeout);
    const parsed = parseReviewResponse(raw);

    if (!parsed) {
      return {
        provider: provider.name,
        model: provider.model,
        score: 0,
        answers: [],
        reasoning: '',
        duration_ms: Math.round(performance.now() - start),
        error: `Failed to parse response from ${provider.name}`,
      };
    }

    const score = computeWeightedScore(parsed.answers);

    return {
      provider: provider.name,
      model: provider.model,
      score,
      answers: parsed.answers,
      reasoning: parsed.reasoning,
      duration_ms: Math.round(performance.now() - start),
    };
  } catch (err) {
    return {
      provider: provider.name,
      model: provider.model,
      score: 0,
      answers: [],
      reasoning: '',
      duration_ms: Math.round(performance.now() - start),
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

function computeDisagreement(reviews: ProviderReview[]): number {
  if (reviews.length < 2) return 0;
  const scores = reviews.map(r => r.score);
  const max = Math.max(...scores);
  const min = Math.min(...scores);
  return max - min;
}
