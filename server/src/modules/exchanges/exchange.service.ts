import { env } from '../../config/env.js';
import { isDatabaseConnected } from '../../database/connection.js';
import { sha256 } from '../crypto/hash.js';
import { verify } from '../crypto/signature.js';
import { analyzeSecurityEvidence } from '../trust/security-analyzer.js';
import { validateContext } from '../context/context.service.js';
import { systemAudit } from '../audit/audit.service.js';
import { validateProvenance } from '../provenance/provenance.service.js';
import { calculateTrustScore, evaluatePolicy, HARD_FAILURE_CODES } from '../trust/trust.engine.js';
import { resourceRisk } from '../trust/trust.types.js';
import { issueTrustPass } from '../trust-pass/trust-pass.service.js';
import type { SourceDocument } from '../sources/source.model.js';
import { getSourceById } from '../sources/source.service.js';
import {
  findExchangeBySourceAndNonce,
  findExchangeByTransactionId,
  findExchanges,
  findLatestSequenceBySource,
  insertExchange,
  updateExchange,
} from './exchange.repository.js';
import type { CreateExchangeInput } from './exchange.schema.js';
import type {
  ExchangeEnvelope,
  ExchangeRecord,
  DecisionResult,
  SignableExchange,
  VerificationChecks,
  ReviewerRecord,
} from './exchange.types.js';

export function getSignableExchange(exchange: ExchangeEnvelope): SignableExchange {
  const { signature, ...signableExchange } = exchange;
  void signature;
  return signableExchange;
}

export async function processExchange(input: CreateExchangeInput): Promise<ExchangeRecord> {
  const existingTransaction = await findExchangeByTransactionId(input.transactionId);
  const verification = await verifyExchange(input, !existingTransaction);

  if (existingTransaction) {
    return buildRecord(input, withReplayDetected(verification));
  }

  let record = buildRecord(input, verification);

  try {
    record = await insertExchange(record);
    if (verification.decision === 'ALLOW' && isDatabaseConnected()) {
      const pass = await issueTrustPass(record);
      const updated = await updateExchange(record.transactionId, { trustPassId: pass.passId });
      record = updated ?? { ...record, trustPassId: pass.passId };
      await systemAudit(record.transactionId, 'TRUST_PASS_ISSUED', [], 'ALLOW', record.payloadHash);
    }
    if (isDatabaseConnected()) {
      await systemAudit(
        record.transactionId,
        verification.decision === 'ALLOW'
          ? 'EXCHANGE_VERIFIED'
          : verification.decision === 'REVIEW'
            ? 'REVIEW_REQUESTED'
            : 'EXCHANGE_QUARANTINED',
        verification.reasonCodes,
        verification.decision,
        record.payloadHash,
      );
    }
    return record;
  } catch (error: unknown) {
    if (isDuplicateKeyError(error)) {
      return buildRecord(input, withReplayDetected(verification));
    }
    throw error;
  }
}

export function listExchangeRecords(): Promise<ExchangeRecord[]> {
  return findExchanges();
}

export async function getExchangeRecord(transactionId: string): Promise<ExchangeRecord> {
  const exchange = await findExchangeByTransactionId(transactionId);
  if (!exchange) {
    throw new ExchangeNotFoundError();
  }
  return exchange;
}

export async function reviewExchange(
  transactionId: string,
  action: 'APPROVE' | 'REJECT',
  reviewerId: string,
  reason: string,
): Promise<ExchangeRecord> {
  const exchange = await getExchangeRecord(transactionId);
  if (exchange.verification.decision !== 'REVIEW')
    throw new ExchangeReviewError(
      'EXCHANGE_NOT_REVIEWABLE',
      'Only REVIEW exchanges may be decided',
    );
  const hardFailure = exchange.verification.reasonCodes.some((code) =>
    HARD_FAILURE_CODES.includes(code as never),
  );
  if (action === 'APPROVE' && hardFailure)
    throw new ExchangeReviewError(
      'HARD_FAILURE_REVIEW_DENIED',
      'Hard security failures cannot be approved',
    );
  const reviewer: ReviewerRecord = {
    reviewerId,
    action,
    reason,
    reviewedAt: new Date().toISOString(),
  };
  const verification = {
    ...exchange.verification,
    decision: action === 'APPROVE' ? ('ALLOW' as const) : ('QUARANTINE' as const),
  };
  const updated = await updateExchange(transactionId, { verification, reviewer });
  if (!updated) throw new ExchangeNotFoundError();
  let result: ExchangeRecord = updated;
  if (action === 'APPROVE') {
    const pass = await issueTrustPass(updated);
    const withPass = await updateExchange(transactionId, { trustPassId: pass.passId });
    result = withPass ?? { ...updated, trustPassId: pass.passId };
    await systemAudit(transactionId, 'HUMAN_APPROVED', [], 'ALLOW', result.payloadHash);
    await systemAudit(transactionId, 'TRUST_PASS_ISSUED', [], 'ALLOW', result.payloadHash);
  } else {
    await systemAudit(
      transactionId,
      'HUMAN_REJECTED',
      ['POLICY_DENIED'],
      'QUARANTINE',
      result.payloadHash,
    );
  }
  return result;
}

export class ExchangeReviewError extends Error {
  public readonly code: 'EXCHANGE_NOT_REVIEWABLE' | 'HARD_FAILURE_REVIEW_DENIED';
  public readonly statusCode = 409;
  public constructor(
    code: 'EXCHANGE_NOT_REVIEWABLE' | 'HARD_FAILURE_REVIEW_DENIED',
    message: string,
  ) {
    super(message);
    this.name = 'ExchangeReviewError';
    this.code = code;
  }
}

export class ExchangeNotFoundError extends Error {
  public readonly code = 'EXCHANGE_NOT_FOUND';
  public readonly statusCode = 404;

  public constructor() {
    super('Exchange was not found');
    this.name = 'ExchangeNotFoundError';
  }
}

async function verifyExchange(
  input: CreateExchangeInput,
  transactionUnique: boolean,
): Promise<DecisionResult> {
  const checks: VerificationChecks = {
    schemaValid: true,
    sourceKnown: false,
    keyKnown: false,
    hashValid: false,
    signatureValid: false,
    sourceActive: false,
    transactionUnique,
    nonceValid: false,
    sequenceValid: false,
    replayValid: false,
    freshnessValid: false,
    provenanceValid: false,
    contextValid: false,
  };
  const reasonCodes: string[] = [];
  let source: SourceDocument | null = null;

  if (!transactionUnique) {
    addReason(reasonCodes, 'REPLAY_DETECTED');
  }

  try {
    source = await getSourceById(input.source.sourceId);
    checks.sourceKnown = true;
  } catch (error: unknown) {
    if (isSourceNotFoundError(error)) {
      addReason(reasonCodes, 'UNKNOWN_SOURCE');
    } else {
      throw error;
    }
  }

  if (source) {
    checks.keyKnown = source.keyId === input.source.keyId;
    if (!checks.keyKnown) {
      addReason(reasonCodes, 'UNKNOWN_KEY');
    }
  }

  checks.hashValid = sha256(input.payload) === input.payloadHash;
  if (!checks.hashValid) {
    addReason(reasonCodes, 'HASH_MISMATCH');
  }

  if (source && checks.keyKnown) {
    checks.signatureValid = verify(getSignableExchange(input), input.signature, source.publicKey);
    if (!checks.signatureValid) {
      addReason(reasonCodes, 'INVALID_SIGNATURE');
    }
  } else {
    addReason(reasonCodes, 'INVALID_SIGNATURE');
  }

  const cryptographicValid =
    checks.sourceKnown && checks.keyKnown && checks.hashValid && checks.signatureValid;

  if (cryptographicValid) {
    const nonceRecord = await findExchangeBySourceAndNonce(input.source.sourceId, input.nonce);
    checks.nonceValid = nonceRecord === null;
    if (!checks.nonceValid) {
      addReason(reasonCodes, 'REPLAY_DETECTED');
    }

    const latestSequenceRecord = await findLatestSequenceBySource(input.source.sourceId);
    checks.sequenceValid =
      latestSequenceRecord === null || input.sequence > latestSequenceRecord.sequence;
    if (!checks.sequenceValid) {
      addReason(reasonCodes, 'REPLAY_DETECTED');
    }
  }

  checks.replayValid =
    cryptographicValid &&
    checks.transactionUnique &&
    checks.nonceValid &&
    checks.sequenceValid &&
    checks.sourceKnown;
  checks.freshnessValid = validateFreshness(input, reasonCodes);

  if (source?.status === 'REVOKED') {
    addReason(reasonCodes, 'REVOKED_SOURCE');
  } else if (source?.status === 'SUSPENDED') {
    addReason(reasonCodes, 'SOURCE_SUSPENDED');
  } else if (source?.status === 'ACTIVE') {
    checks.sourceActive = true;
  }

  if (cryptographicValid) {
    const provenance = await validateProvenance(input.provenance, input.payloadHash);
    checks.provenanceValid = provenance.valid;
    for (const reasonCode of provenance.reasonCodes) {
      addReason(reasonCodes, reasonCode);
    }
  }

  if (cryptographicValid) {
    const context = validateContext(input);
    checks.contextValid = context.valid;
    for (const reasonCode of context.reasonCodes) addReason(reasonCodes, reasonCode);
  }
  const selectedResourceRisk = resourceRisk[input.resourceType] ?? 'HIGH';
  const securityAssessment = analyzeSecurityEvidence({
    checks,
    reasonCodes,
    resourceRisk: selectedResourceRisk,
  });
  const trust = calculateTrustScore({ checks, securityAssessment });
  const policy = evaluatePolicy({
    checks,
    securityAssessment,
    score: trust.score,
    reasonCodes,
    resourceRisk: selectedResourceRisk,
  });
  const decision = policy.decision;

  return {
    decision,
    reasonCodes,
    checks,
    sourceId: input.source.sourceId,
    keyId: input.source.keyId,
    payloadHash: input.payloadHash,
    verifiedAt: new Date().toISOString(),
    resourceRisk: selectedResourceRisk,
    securityAssessment,
    trustScore: trust.score,
    riskLevel: securityAssessment.riskLevel,
  };
}

function validateFreshness(input: CreateExchangeInput, reasonCodes: string[]): boolean {
  const issuedAt = Date.parse(input.issuedAt);
  const expiresAt = Date.parse(input.expiresAt);
  const now = Date.now();
  let valid = true;

  if (expiresAt <= now || expiresAt <= issuedAt) {
    addReason(reasonCodes, 'EXPIRED_MESSAGE');
    valid = false;
  }
  if (issuedAt > now + env.MAX_CLOCK_SKEW_MS) {
    addReason(reasonCodes, 'FUTURE_MESSAGE');
    valid = false;
  }
  if (expiresAt - issuedAt > env.MAX_MESSAGE_TTL_MS) {
    addReason(reasonCodes, 'MESSAGE_TTL_EXCEEDED');
    valid = false;
  }

  return valid;
}

function buildRecord(input: CreateExchangeInput, verification: DecisionResult): ExchangeRecord {
  const now = new Date();
  return {
    ...input,
    verification: {
      decision: verification.decision,
      reasonCodes: verification.reasonCodes,
      checks: verification.checks,
      sourceId: verification.sourceId,
      keyId: verification.keyId,
      payloadHash: verification.payloadHash,
      verifiedAt: verification.verifiedAt,
    },
    resourceRisk: verification.resourceRisk,
    securityAssessment: verification.securityAssessment,
    trustScore: verification.trustScore,
    riskLevel: verification.riskLevel,
    createdAt: now,
    updatedAt: now,
  };
}

function withReplayDetected(verification: DecisionResult): DecisionResult {
  const reasonCodes = [...verification.reasonCodes];
  addReason(reasonCodes, 'REPLAY_DETECTED');
  return {
    ...verification,
    decision: 'QUARANTINE',
    reasonCodes,
    checks: {
      ...verification.checks,
      transactionUnique: false,
      replayValid: false,
    },
  };
}

function addReason(reasonCodes: string[], code: string): void {
  if (!reasonCodes.includes(code)) {
    reasonCodes.push(code);
  }
}

function isSourceNotFoundError(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    error.code === 'SOURCE_NOT_FOUND'
  );
}

function isDuplicateKeyError(error: unknown): error is { code: 11000 } {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 11000;
}
