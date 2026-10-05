import { generateEd25519KeyPair, sign } from '../src/modules/crypto/signature.js';
import { sha256 } from '../src/modules/crypto/hash.js';
import { getSignableExchange, processExchange } from '../src/modules/exchanges/exchange.service.js';
import type { CreateExchangeInput } from '../src/modules/exchanges/exchange.schema.js';
import type { SourceDocument } from '../src/modules/sources/source.model.js';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const repository = vi.hoisted(() => ({
  findExchangeBySourceAndNonce: vi.fn(),
  findExchangeByTransactionId: vi.fn(),
  findExchanges: vi.fn(),
  findLatestSequenceBySource: vi.fn(),
  insertExchange: vi.fn(),
}));

const sources = vi.hoisted(() => ({ getSourceById: vi.fn() }));

vi.mock('../src/modules/exchanges/exchange.repository.js', () => repository);
vi.mock('../src/modules/sources/source.service.js', () => sources);

const keyPair = generateEd25519KeyPair();
const publicKey = keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();

function makeSource(status: 'ACTIVE' | 'SUSPENDED' | 'REVOKED' = 'ACTIVE') {
  return {
    sourceId: 'LAB-A',
    name: 'Laboratory A',
    role: 'SOURCE',
    type: 'LAB',
    status,
    keyId: 'lab-a-key-1',
    publicKey,
    allowedTransformations: [],
    createdAt: new Date(),
    updatedAt: new Date(),
  } as unknown as SourceDocument;
}

function makeExchange(overrides: Partial<CreateExchangeInput> = {}): CreateExchangeInput {
  const now = Date.now();
  const payload = {
    resourceType: 'Observation',
    patientRef: 'PAT-1001',
    encounterRef: 'ENC-1001',
    data: { test: 'Glucose', value: 120, unit: 'mg/dL' },
  };
  const exchangeWithoutSignature: Omit<CreateExchangeInput, 'signature'> = {
    transactionId: 'TX-VERIFY-001',
    source: { sourceId: 'LAB-A', keyId: 'lab-a-key-1' },
    resourceType: 'Observation',
    context: {
      patientRef: 'PAT-1001',
      encounterRef: 'ENC-1001',
      purpose: 'clinical-decision-support',
      audience: 'CLINICAL-AI',
    },
    payload,
    issuedAt: new Date(now - 1_000).toISOString(),
    expiresAt: new Date(now + 299_000).toISOString(),
    sequence: 1,
    nonce: 'nonce-verify-001',
    payloadHash: sha256(payload),
    provenance: {
      originSourceId: 'LAB-A',
      originHash: sha256(payload),
      transformations: [],
    },
  };
  const base = { ...exchangeWithoutSignature, ...overrides } as CreateExchangeInput;
  return {
    ...base,
    signature: sign(getSignableExchange({ ...base, signature: '' }), keyPair.privateKey),
  };
}

describe('exchange verification pipeline', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    repository.findExchangeByTransactionId.mockResolvedValue(null);
    repository.findExchangeBySourceAndNonce.mockResolvedValue(null);
    repository.findLatestSequenceBySource.mockResolvedValue(null);
    repository.insertExchange.mockImplementation(async (record) => record);
    sources.getSourceById.mockResolvedValue(makeSource());
  });

  it('allows a clean exchange with a known active source and valid signature', async () => {
    const result = await processExchange(makeExchange());

    expect(result.verification.decision).toBe('ALLOW');
    expect(result.verification.reasonCodes).toEqual([]);
    expect(result.verification.checks).toEqual({
      schemaValid: true,
      sourceKnown: true,
      keyKnown: true,
      hashValid: true,
      signatureValid: true,
      sourceActive: true,
      transactionUnique: true,
      nonceValid: true,
      sequenceValid: true,
      replayValid: true,
      freshnessValid: true,
      provenanceValid: true,
    });
  });

  it('quarantines an unknown source', async () => {
    sources.getSourceById.mockRejectedValue({ code: 'SOURCE_NOT_FOUND' });

    const result = await processExchange(
      makeExchange({
        source: { sourceId: 'UNKNOWN-SOURCE', keyId: 'unknown-source-key-1' },
      }),
    );

    expect(result.verification.decision).toBe('QUARANTINE');
    expect(result.verification.reasonCodes).toContain('UNKNOWN_SOURCE');
  });

  it('quarantines an unknown key for a known source', async () => {
    const exchange = makeExchange({ source: { sourceId: 'LAB-A', keyId: 'wrong-key-1' } });

    const result = await processExchange(exchange);

    expect(result.verification.decision).toBe('QUARANTINE');
    expect(result.verification.reasonCodes).toContain('UNKNOWN_KEY');
  });

  it('quarantines a tampered payload', async () => {
    const exchange = makeExchange();
    exchange.payload.data.value = 999;

    const result = await processExchange(exchange);

    expect(result.verification.decision).toBe('QUARANTINE');
    expect(result.verification.reasonCodes).toContain('HASH_MISMATCH');
  });

  it('quarantines a mutated signature', async () => {
    const exchange = makeExchange();
    exchange.signature = `${exchange.signature.startsWith('A') ? 'B' : 'A'}${exchange.signature.slice(1)}`;

    const result = await processExchange(exchange);

    expect(result.verification.decision).toBe('QUARANTINE');
    expect(result.verification.reasonCodes).toContain('INVALID_SIGNATURE');
  });

  it('quarantines a revoked source and reviews a suspended source', async () => {
    sources.getSourceById.mockResolvedValueOnce(makeSource('REVOKED'));
    const revoked = await processExchange(makeExchange({ transactionId: 'TX-REVOKED' }));
    expect(revoked.verification.decision).toBe('QUARANTINE');
    expect(revoked.verification.reasonCodes).toContain('REVOKED_SOURCE');

    sources.getSourceById.mockResolvedValueOnce(makeSource('SUSPENDED'));
    const suspended = await processExchange(makeExchange({ transactionId: 'TX-SUSPENDED' }));
    expect(suspended.verification.decision).toBe('REVIEW');
    expect(suspended.verification.reasonCodes).toContain('SOURCE_SUSPENDED');
  });

  it('rejects duplicate transaction IDs before processing a second exchange', async () => {
    repository.findExchangeByTransactionId.mockResolvedValue({ transactionId: 'TX-DUPLICATE' });

    const result = await processExchange(makeExchange({ transactionId: 'TX-DUPLICATE' }));

    expect(result.verification.decision).toBe('QUARANTINE');
    expect(result.verification.reasonCodes).toContain('REPLAY_DETECTED');
    expect(result.verification.checks.transactionUnique).toBe(false);
  });

  it('quarantines a reused nonce for the same source', async () => {
    repository.findExchangeBySourceAndNonce.mockResolvedValue({ transactionId: 'TX-OLD' });

    const result = await processExchange(makeExchange({ transactionId: 'TX-NONCE-REPLAY' }));

    expect(result.verification.decision).toBe('QUARANTINE');
    expect(result.verification.reasonCodes).toContain('REPLAY_DETECTED');
    expect(result.verification.checks.nonceValid).toBe(false);
    expect(result.verification.checks.replayValid).toBe(false);
  });

  it('quarantines a sequence number that is not greater than the latest seen value', async () => {
    repository.findLatestSequenceBySource.mockResolvedValue({ sequence: 4 });

    const result = await processExchange(makeExchange({ sequence: 4 }));

    expect(result.verification.decision).toBe('QUARANTINE');
    expect(result.verification.reasonCodes).toContain('REPLAY_DETECTED');
    expect(result.verification.checks.sequenceValid).toBe(false);
  });

  it('quarantines expired and future-dated messages', async () => {
    const expired = await processExchange(
      makeExchange({
        transactionId: 'TX-EXPIRED',
        issuedAt: new Date(Date.now() - 120_000).toISOString(),
        expiresAt: new Date(Date.now() - 60_000).toISOString(),
      }),
    );
    expect(expired.verification.decision).toBe('QUARANTINE');
    expect(expired.verification.reasonCodes).toContain('EXPIRED_MESSAGE');

    const future = await processExchange(
      makeExchange({
        transactionId: 'TX-FUTURE',
        issuedAt: new Date(Date.now() + 120_000).toISOString(),
        expiresAt: new Date(Date.now() + 420_000).toISOString(),
      }),
    );
    expect(future.verification.decision).toBe('QUARANTINE');
    expect(future.verification.reasonCodes).toContain('FUTURE_MESSAGE');
  });

  it('quarantines messages whose declared lifetime exceeds the configured maximum', async () => {
    const result = await processExchange(
      makeExchange({
        transactionId: 'TX-TTL-EXCEEDED',
        issuedAt: new Date(Date.now() - 1_000).toISOString(),
        expiresAt: new Date(Date.now() + 601_000).toISOString(),
      }),
    );

    expect(result.verification.decision).toBe('QUARANTINE');
    expect(result.verification.reasonCodes).toContain('MESSAGE_TTL_EXCEEDED');
    expect(result.verification.checks.freshnessValid).toBe(false);
  });
});
