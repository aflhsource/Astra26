import { sha256 } from '../src/modules/crypto/hash.js';
import type { ExchangeProvenance } from '../src/modules/exchanges/exchange.types.js';
import { validateProvenance } from '../src/modules/provenance/provenance.service.js';
import type { SourceDocument } from '../src/modules/sources/source.model.js';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const sources = vi.hoisted(() => ({ getSourceById: vi.fn() }));
vi.mock('../src/modules/sources/source.service.js', () => sources);

const integrationSource = {
  sourceId: 'INTEGRATION-A',
  role: 'TRANSFORMER',
  status: 'ACTIVE',
  allowedTransformations: ['NORMALIZE_UNIT'],
} as unknown as SourceDocument;
const labSource = {
  sourceId: 'LAB-A',
  role: 'SOURCE',
  status: 'ACTIVE',
  allowedTransformations: [],
} as unknown as SourceDocument;
const consumerSource = {
  sourceId: 'CLINICAL-AI',
  role: 'CONSUMER',
  status: 'ACTIVE',
  allowedTransformations: [],
} as unknown as SourceDocument;

const hash1 = sha256({ value: 1 });
const hash2 = sha256({ value: 2 });
const hash3 = sha256({ value: 3 });
const timestamp = new Date(Date.now() - 1_000).toISOString();

function directProvenance(): ExchangeProvenance {
  return { originSourceId: 'LAB-A', originHash: hash1, transformations: [] };
}

function validChain(): ExchangeProvenance {
  return {
    originSourceId: 'LAB-A',
    originHash: hash1,
    transformations: [
      {
        actorId: 'INTEGRATION-A',
        operation: 'NORMALIZE_UNIT',
        inputHash: hash1,
        outputHash: hash2,
        timestamp,
      },
      {
        actorId: 'INTEGRATION-A',
        operation: 'NORMALIZE_UNIT',
        inputHash: hash2,
        outputHash: hash3,
        timestamp,
      },
    ],
  };
}

describe('provenance validation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sources.getSourceById.mockImplementation(async (sourceId: string) => {
      if (sourceId === 'LAB-A') return labSource;
      if (sourceId === 'INTEGRATION-A') return integrationSource;
      if (sourceId === 'CLINICAL-AI') return consumerSource;
      throw { code: 'SOURCE_NOT_FOUND' };
    });
  });

  it('allows a known direct source when originHash equals payloadHash', async () => {
    await expect(validateProvenance(directProvenance(), hash1)).resolves.toEqual({
      valid: true,
      reasonCodes: [],
    });
  });

  it('allows a continuous multi-transformation chain', async () => {
    await expect(validateProvenance(validChain(), hash3)).resolves.toEqual({
      valid: true,
      reasonCodes: [],
    });
  });

  it('rejects an unauthorized operation', async () => {
    const provenance = validChain();
    provenance.transformations[0]!.operation = 'DELETE_DIAGNOSTIC_VALUE';

    const result = await validateProvenance(provenance, hash3);

    expect(result.valid).toBe(false);
    expect(result.reasonCodes).toEqual(
      expect.arrayContaining(['UNAUTHORIZED_TRANSFORMATION', 'PROVENANCE_FAILURE']),
    );
  });

  it('rejects an unknown actor and a consumer actor', async () => {
    const unknown = validChain();
    unknown.transformations[0]!.actorId = 'UNKNOWN-A';
    const unknownResult = await validateProvenance(unknown, hash3);
    expect(unknownResult.reasonCodes).toEqual(
      expect.arrayContaining(['UNKNOWN_TRANSFORMATION_ACTOR', 'PROVENANCE_FAILURE']),
    );

    const consumer = validChain();
    consumer.transformations[0]!.actorId = 'CLINICAL-AI';
    const consumerResult = await validateProvenance(consumer, hash3);
    expect(consumerResult.reasonCodes).toEqual(
      expect.arrayContaining(['INVALID_TRANSFORMATION_ACTOR_ROLE', 'PROVENANCE_FAILURE']),
    );
  });

  it('rejects broken input and final output hash links', async () => {
    const brokenInput = validChain();
    brokenInput.transformations[1]!.inputHash = sha256({ value: 999 });
    const inputResult = await validateProvenance(brokenInput, hash3);
    expect(inputResult.reasonCodes).toContain('PROVENANCE_HASH_MISMATCH');

    const brokenFinal = validChain();
    const finalResult = await validateProvenance(brokenFinal, sha256({ value: 999 }));
    expect(finalResult.reasonCodes).toContain('PROVENANCE_HASH_MISMATCH');
  });

  it('rejects an unknown origin source and a future transformation timestamp', async () => {
    const unknownOrigin = directProvenance();
    unknownOrigin.originSourceId = 'UNKNOWN-ORIGIN';
    const originResult = await validateProvenance(unknownOrigin, hash1);
    expect(originResult.reasonCodes).toEqual(
      expect.arrayContaining(['UNKNOWN_ORIGIN_SOURCE', 'PROVENANCE_FAILURE']),
    );

    const future = validChain();
    future.transformations[0]!.timestamp = new Date(Date.now() + 120_000).toISOString();
    const futureResult = await validateProvenance(future, hash3);
    expect(futureResult.reasonCodes).toContain('PROVENANCE_FAILURE');
  });
});
