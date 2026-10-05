import type {
  SecurityAssessment,
  ExchangeDecision,
  ExchangeRecord,
  RiskLevel,
  VerificationChecks,
} from '../exchanges/exchange.types.js';

export const resourceRisk: Record<string, RiskLevel> = {
  Observation: 'HIGH',
  DiagnosticReport: 'HIGH',
  MedicationRequest: 'CRITICAL',
  AllergyIntolerance: 'CRITICAL',
  DemographicUpdate: 'MEDIUM',
};

export interface TrustScoreInput {
  checks: VerificationChecks;
  securityAssessment: SecurityAssessment;
}

export interface TrustScoreResult {
  score: number;
  components: Record<string, number>;
}

export interface PolicyInput extends TrustScoreInput {
  score: number;
  reasonCodes: string[];
  resourceRisk: RiskLevel;
}

export interface PolicyResult {
  decision: ExchangeDecision;
  hardFailure: boolean;
}

export type ExchangeLike = Pick<ExchangeRecord, 'resourceType' | 'context' | 'payload'>;
