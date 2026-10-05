export const resourceTypes = [
  'Observation',
  'MedicationRequest',
  'AllergyIntolerance',
  'DiagnosticReport',
  'DemographicUpdate',
] as const;
export type ResourceType = (typeof resourceTypes)[number];

export const exchangeDecisions = ['ALLOW', 'REVIEW', 'QUARANTINE'] as const;
export type ExchangeDecision = (typeof exchangeDecisions)[number];

export const riskLevels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
export type RiskLevel = (typeof riskLevels)[number];

export interface ExchangeSource {
  sourceId: string;
  keyId: string;
}

export interface ExchangeContext {
  patientRef: string;
  encounterRef: string;
  purpose: string;
  audience: string;
}

export interface ExchangePayload {
  resourceType: string;
  patientRef: string;
  encounterRef: string;
  data: Record<string, unknown>;
}

export interface Transformation {
  actorId: string;
  operation: string;
  inputHash: string;
  outputHash: string;
  timestamp: string;
}

export interface ExchangeProvenance {
  originSourceId: string;
  originHash: string;
  transformations: Transformation[];
}

export interface ExchangeEnvelope {
  transactionId: string;
  source: ExchangeSource;
  resourceType: ResourceType;
  context: ExchangeContext;
  payload: ExchangePayload;
  issuedAt: string;
  expiresAt: string;
  sequence: number;
  nonce: string;
  payloadHash: string;
  provenance: ExchangeProvenance;
  signature: string;
}

export type SignableExchange = Omit<ExchangeEnvelope, 'signature'>;

export interface VerificationChecks {
  schemaValid: boolean;
  sourceKnown: boolean;
  keyKnown: boolean;
  hashValid: boolean;
  signatureValid: boolean;
  sourceActive: boolean;
  transactionUnique: boolean;
  nonceValid: boolean;
  sequenceValid: boolean;
  replayValid: boolean;
  freshnessValid: boolean;
  provenanceValid: boolean;
  contextValid: boolean;
}

export interface SecurityAssessment {
  riskLevel: RiskLevel;
  anomalyScore: number;
  probability: number;
  confidence: number;
  findings: string[];
  recommendation: 'ALLOW' | 'REVIEW' | 'QUARANTINE';
}

export interface ReviewerRecord {
  reviewerId: string;
  action: 'APPROVE' | 'REJECT';
  reason: string;
  reviewedAt: string;
}

export interface VerificationResult {
  decision: ExchangeDecision;
  reasonCodes: string[];
  checks: VerificationChecks;
  sourceId: string;
  keyId: string;
  payloadHash: string;
  verifiedAt: string;
}

export interface DecisionResult extends VerificationResult {
  resourceRisk: RiskLevel;
  securityAssessment: SecurityAssessment;
  trustScore: number;
  riskLevel: RiskLevel;
}

export interface ExchangeRecord extends ExchangeEnvelope {
  verification: VerificationResult;
  resourceRisk: RiskLevel;
  securityAssessment: SecurityAssessment;
  trustScore: number;
  riskLevel: RiskLevel;
  reviewer?: ReviewerRecord;
  trustPassId?: string;
  createdAt: Date;
  updatedAt: Date;
}
