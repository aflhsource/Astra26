import type { ExchangeDecision, RiskLevel } from '../exchanges/exchange.types.js';
import type {
  PolicyInput,
  PolicyResult,
  TrustScoreInput,
  TrustScoreResult,
} from './trust.types.js';

export const HARD_FAILURE_CODES = [
  'UNKNOWN_SOURCE',
  'UNKNOWN_KEY',
  'HASH_MISMATCH',
  'INVALID_SIGNATURE',
  'REVOKED_SOURCE',
  'REPLAY_DETECTED',
  'EXPIRED_MESSAGE',
  'FUTURE_MESSAGE',
  'MESSAGE_TTL_EXCEEDED',
  'PROVENANCE_FAILURE',
  'UNKNOWN_ORIGIN_SOURCE',
  'UNKNOWN_TRANSFORMATION_ACTOR',
  'INVALID_TRANSFORMATION_ACTOR_ROLE',
  'UNAUTHORIZED_TRANSFORMATION',
  'PROVENANCE_HASH_MISMATCH',
] as const;

export function calculateTrustScore(input: TrustScoreInput): TrustScoreResult {
  const { checks, securityAssessment } = input;
  const components = {
    cryptographicIntegrity: checks.hashValid && checks.signatureValid ? 30 : 0,
    provenanceContinuity: checks.provenanceValid ? 20 : 0,
    sourceAuthorization: checks.sourceKnown && checks.sourceActive ? 15 : 0,
    transformationValidity: checks.provenanceValid ? 10 : 0,
    freshnessReplay: checks.freshnessValid && checks.replayValid ? 10 : 0,
    schemaContext: checks.schemaValid && checks.contextValid ? 5 : 0,
    securityAnomaly: Math.max(0, Math.min(10, 10 * (1 - securityAssessment.anomalyScore / 100))),
  };
  return {
    score: Math.round(Object.values(components).reduce((sum, value) => sum + value, 0)),
    components,
  };
}

export function evaluatePolicy(input: PolicyInput): PolicyResult {
  const hardFailure = input.reasonCodes.some((code) => HARD_FAILURE_CODES.includes(code as never));
  if (hardFailure || input.score < 60) return { decision: 'QUARANTINE', hardFailure };
  if (
    !input.checks.contextValid ||
    input.securityAssessment.riskLevel === 'HIGH' ||
    input.securityAssessment.riskLevel === 'CRITICAL'
  ) {
    return { decision: 'REVIEW', hardFailure: false };
  }
  if (input.resourceRisk === 'CRITICAL' && input.securityAssessment.anomalyScore >= 20) {
    return { decision: 'REVIEW', hardFailure: false };
  }
  return { decision: input.score >= 85 ? 'ALLOW' : 'REVIEW', hardFailure: false };
}

export function riskLevelFromProbability(probability: number): RiskLevel {
  if (probability >= 0.8) return 'CRITICAL';
  if (probability >= 0.5) return 'HIGH';
  if (probability >= 0.2) return 'MEDIUM';
  return 'LOW';
}

export function decisionForRisk(riskLevel: RiskLevel): ExchangeDecision {
  return riskLevel === 'CRITICAL' || riskLevel === 'HIGH' ? 'REVIEW' : 'ALLOW';
}
