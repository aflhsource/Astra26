import { env } from '../../config/env.js';
import { sha256 } from '../crypto/hash.js';
import { verify } from '../crypto/signature.js';
import type { SourceDocument } from '../sources/source.model.js';
import { getSourceById } from '../sources/source.service.js';
import {
  findExchangeBySourceAndNonce,
  findExchangeByTransactionId,
  findExchanges,
  findLatestSequenceBySource,
  insertExchange,
} from './exchange.repository.js';
import type { CreateExchangeInput } from './exchange.schema.js';
import type {
  ExchangeEnvelope,
  ExchangeRecord,
  SignableExchange,
  VerificationChecks,
  VerificationResult,
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

  const record = buildRecord(input, verification);

  try {
    return await insertExchange(record);
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
): Promise<VerificationResult> {
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

  if (source) {
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
    checks.transactionUnique && checks.nonceValid && checks.sequenceValid && checks.sourceKnown;
  checks.freshnessValid = validateFreshness(input, reasonCodes);

  if (source?.status === 'REVOKED') {
    addReason(reasonCodes, 'REVOKED_SOURCE');
  } else if (source?.status === 'SUSPENDED') {
    addReason(reasonCodes, 'SOURCE_SUSPENDED');
  } else if (source?.status === 'ACTIVE') {
    checks.sourceActive = true;
  }

  const hardFailure = reasonCodes.some((code) =>
    [
      'UNKNOWN_SOURCE',
      'UNKNOWN_KEY',
      'HASH_MISMATCH',
      'INVALID_SIGNATURE',
      'REVOKED_SOURCE',
      'REPLAY_DETECTED',
      'EXPIRED_MESSAGE',
      'FUTURE_MESSAGE',
      'MESSAGE_TTL_EXCEEDED',
    ].includes(code),
  );
  const decision = hardFailure
    ? 'QUARANTINE'
    : reasonCodes.includes('SOURCE_SUSPENDED')
      ? 'REVIEW'
      : 'ALLOW';

  return {
    decision,
    reasonCodes,
    checks,
    sourceId: input.source.sourceId,
    keyId: input.source.keyId,
    payloadHash: input.payloadHash,
    verifiedAt: new Date().toISOString(),
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

function buildRecord(input: CreateExchangeInput, verification: VerificationResult): ExchangeRecord {
  const now = new Date();
  return { ...input, verification, createdAt: now, updatedAt: now };
}

function withReplayDetected(verification: VerificationResult): VerificationResult {
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
