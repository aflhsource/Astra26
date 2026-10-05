import type {
  RiskLevel,
  SecurityAssessment,
  VerificationChecks,
} from '../exchanges/exchange.types.js';
import { decisionForRisk, riskLevelFromProbability } from './trust.engine.js';

export interface SecurityEvidence {
  checks: VerificationChecks;
  reasonCodes: string[];
  resourceRisk: RiskLevel;
}

export function analyzeSecurityEvidence(evidence: SecurityEvidence): SecurityAssessment {
  const findings: string[] = [];
  let probability = 0.02;
  const { checks, reasonCodes, resourceRisk } = evidence;
  if (!checks.hashValid) {
    probability += 0.45;
    findings.push('Payload integrity evidence failed');
  }
  if (!checks.signatureValid) {
    probability += 0.45;
    findings.push('Digital signature evidence failed');
  }
  if (!checks.provenanceValid) {
    probability += 0.25;
    findings.push('Provenance continuity is incomplete');
  }
  if (!checks.contextValid) {
    probability += 0.35;
    findings.push('Context inconsistency detected');
  }
  if (!checks.replayValid) {
    probability += 0.35;
    findings.push('Replay evidence failed');
  }
  if (!checks.freshnessValid) {
    probability += 0.3;
    findings.push('Message freshness evidence failed');
  }
  if (resourceRisk === 'CRITICAL') {
    probability += 0.08;
    findings.push('Critical-impact resource');
  }
  if (resourceRisk === 'HIGH') findings.push('High-impact resource');
  if (reasonCodes.includes('SOURCE_SUSPENDED')) {
    probability += 0.2;
    findings.push('Source is suspended');
  }
  probability = Math.min(1, probability);
  const riskLevel = riskLevelFromProbability(probability);
  return {
    riskLevel,
    anomalyScore: Math.round(probability * 100),
    probability,
    confidence: findings.length > 0 ? 0.91 : 0.88,
    findings,
    recommendation: decisionForRisk(riskLevel),
  };
}
