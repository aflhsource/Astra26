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

export interface ExchangeRecord extends ExchangeEnvelope {
  verification: VerificationResult;
  createdAt: Date;
  updatedAt: Date;
}
