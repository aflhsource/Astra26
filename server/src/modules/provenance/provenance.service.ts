import { env } from '../../config/env.js';
import type { ExchangeProvenance } from '../exchanges/exchange.types.js';
import { getSourceById } from '../sources/source.service.js';
import type { ProvenanceValidationResult } from './provenance.types.js';

export async function validateProvenance(
  provenance: ExchangeProvenance,
  payloadHash: string,
  now = Date.now(),
): Promise<ProvenanceValidationResult> {
  const reasonCodes: string[] = [];
  const originSourceKnown = await sourceExists(provenance.originSourceId, reasonCodes, 'origin');

  if (!isHash(provenance.originHash)) {
    addReason(reasonCodes, 'PROVENANCE_FAILURE');
  }

  let expectedHash = provenance.originHash;

  if (provenance.transformations.length === 0) {
    if (expectedHash !== payloadHash) {
      addReason(reasonCodes, 'PROVENANCE_HASH_MISMATCH');
    }
  } else {
    for (const transformation of provenance.transformations) {
      if (!transformation.actorId || !transformation.operation) {
        addReason(reasonCodes, 'PROVENANCE_FAILURE');
        continue;
      }

      const timestamp = Date.parse(transformation.timestamp);
      if (!Number.isFinite(timestamp) || timestamp > now + env.MAX_CLOCK_SKEW_MS) {
        addReason(reasonCodes, 'PROVENANCE_FAILURE');
      }

      const actor = await getActor(transformation.actorId, reasonCodes);
      if (actor) {
        if (actor.role !== 'TRANSFORMER') {
          addReason(reasonCodes, 'INVALID_TRANSFORMATION_ACTOR_ROLE');
          addReason(reasonCodes, 'PROVENANCE_FAILURE');
        }
        if (actor.status !== 'ACTIVE') {
          addReason(reasonCodes, 'PROVENANCE_FAILURE');
        }
        if (!actor.allowedTransformations.includes(transformation.operation)) {
          addReason(reasonCodes, 'UNAUTHORIZED_TRANSFORMATION');
          addReason(reasonCodes, 'PROVENANCE_FAILURE');
        }
      }

      if (!isHash(transformation.inputHash) || !isHash(transformation.outputHash)) {
        addReason(reasonCodes, 'PROVENANCE_FAILURE');
      }
      if (expectedHash !== transformation.inputHash) {
        addReason(reasonCodes, 'PROVENANCE_HASH_MISMATCH');
      }
      expectedHash = transformation.outputHash;
    }

    if (expectedHash !== payloadHash) {
      addReason(reasonCodes, 'PROVENANCE_HASH_MISMATCH');
    }
  }

  if (!originSourceKnown) {
    addReason(reasonCodes, 'PROVENANCE_FAILURE');
  }

  return { valid: reasonCodes.length === 0, reasonCodes };
}

async function sourceExists(
  sourceId: string,
  reasonCodes: string[],
  sourceKind: 'origin',
): Promise<boolean> {
  try {
    await getSourceById(sourceId);
    return true;
  } catch (error: unknown) {
    if (isSourceNotFoundError(error)) {
      addReason(
        reasonCodes,
        sourceKind === 'origin' ? 'UNKNOWN_ORIGIN_SOURCE' : 'PROVENANCE_FAILURE',
      );
      return false;
    }
    throw error;
  }
}

async function getActor(actorId: string, reasonCodes: string[]) {
  try {
    return await getSourceById(actorId);
  } catch (error: unknown) {
    if (isSourceNotFoundError(error)) {
      addReason(reasonCodes, 'UNKNOWN_TRANSFORMATION_ACTOR');
      addReason(reasonCodes, 'PROVENANCE_FAILURE');
      return null;
    }
    throw error;
  }
}

function isHash(value: string): boolean {
  return /^[a-f0-9]{64}$/.test(value);
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
