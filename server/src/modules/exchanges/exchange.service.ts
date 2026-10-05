import { verify } from '../crypto/signature.js';
import { getSourceById } from '../sources/source.service.js';
import type { SourceDocument } from '../sources/source.model.js';
import { sha256 } from '../crypto/hash.js';
import {
  findExchangeByTransactionId,
  findExchanges,
  insertExchange,
} from './exchange.repository.js';
import type { CreateExchangeInput } from './exchange.schema.js';
import type {
  ExchangeEnvelope,
  ExchangeRecord,
  SignableExchange,
  VerificationResult,
} from './exchange.types.js';

export class ExchangeServiceError extends Error {
  public readonly code: 'DUPLICATE_TRANSACTION';
  public readonly statusCode = 409;

  public constructor() {
    super('An exchange with this transactionId already exists');
    this.name = 'ExchangeServiceError';
    this.code = 'DUPLICATE_TRANSACTION';
  }
}

export function getSignableExchange(exchange: ExchangeEnvelope): SignableExchange {
  const { signature, ...signableExchange } = exchange;
  void signature;
  return signableExchange;
}

export async function processExchange(input: CreateExchangeInput): Promise<ExchangeRecord> {
  const existing = await findExchangeByTransactionId(input.transactionId);
  if (existing) {
    throw new ExchangeServiceError();
  }

  const verification = await verifyExchange(input);
  const record: ExchangeRecord = {
    ...input,
    verification,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  try {
    return await insertExchange(record);
  } catch (error: unknown) {
    if (isDuplicateKeyError(error)) {
      throw new ExchangeServiceError();
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

async function verifyExchange(input: CreateExchangeInput): Promise<VerificationResult> {
  const checks: VerificationResult['checks'] = {
    schemaValid: true,
    sourceKnown: false,
    keyKnown: false,
    hashValid: false,
    signatureValid: false,
    sourceActive: false,
  };
  const reasonCodes: string[] = [];
  let source: SourceDocument | null = null;

  try {
    source = await getSourceById(input.source.sourceId);
    checks.sourceKnown = true;
  } catch (error: unknown) {
    if (isSourceNotFoundError(error)) {
      reasonCodes.push('UNKNOWN_SOURCE');
    } else {
      throw error;
    }
  }

  if (source) {
    checks.keyKnown = source.keyId === input.source.keyId;
    if (!checks.keyKnown) {
      reasonCodes.push('UNKNOWN_KEY');
    }
  }

  checks.hashValid = sha256(input.payload) === input.payloadHash;
  if (!checks.hashValid) {
    reasonCodes.push('HASH_MISMATCH');
  }

  if (source && checks.keyKnown) {
    checks.signatureValid = verify(getSignableExchange(input), input.signature, source.publicKey);
    if (!checks.signatureValid) {
      reasonCodes.push('INVALID_SIGNATURE');
    }
  } else {
    reasonCodes.push('INVALID_SIGNATURE');
  }

  if (source?.status === 'REVOKED') {
    reasonCodes.push('REVOKED_SOURCE');
  } else if (source?.status === 'SUSPENDED') {
    reasonCodes.push('SOURCE_SUSPENDED');
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
