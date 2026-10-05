import { z } from 'zod';
import { resourceTypes } from './exchange.types.js';

const identifier = z.string().trim().min(1).max(200);
const isoTimestamp = z.string().datetime({ offset: true });

const sourceSchema = z.object({
  sourceId: identifier,
  keyId: identifier,
});

const contextSchema = z.object({
  patientRef: identifier,
  encounterRef: identifier,
  purpose: identifier,
  audience: identifier,
});

const payloadSchema = z.object({
  resourceType: identifier,
  patientRef: identifier,
  encounterRef: identifier,
  data: z.record(z.string(), z.unknown()),
});

const transformationSchema = z.object({
  actorId: identifier,
  operation: identifier,
  inputHash: z.string().regex(/^[a-f0-9]{64}$/),
  outputHash: z.string().regex(/^[a-f0-9]{64}$/),
  timestamp: isoTimestamp,
});

const provenanceSchema = z.object({
  originSourceId: identifier,
  originHash: z.string().regex(/^[a-f0-9]{64}$/),
  transformations: z.array(transformationSchema),
});

export const exchangeEnvelopeSchema = z.object({
  transactionId: identifier,
  source: sourceSchema,
  resourceType: z.enum(resourceTypes),
  context: contextSchema,
  payload: payloadSchema,
  issuedAt: isoTimestamp,
  expiresAt: isoTimestamp,
  sequence: z.number().int().positive(),
  nonce: identifier,
  payloadHash: z.string().regex(/^[a-f0-9]{64}$/),
  provenance: provenanceSchema,
  signature: z.string().min(1),
});

export const createExchangeSchema = z.object({
  body: exchangeEnvelopeSchema,
  params: z.object({}),
  query: z.object({}),
});

export const exchangeTransactionSchema = z.object({
  body: z.unknown().optional(),
  params: z.object({ transactionId: identifier }),
  query: z.object({}),
});

export const listExchangesSchema = z.object({
  body: z.unknown().optional(),
  params: z.object({}),
  query: z.object({}),
});

export const exchangeDecisionSchema = z.object({
  body: z.object({
    action: z.enum(['APPROVE', 'REJECT']),
    reviewerId: identifier,
    reason: z.string().trim().min(1).max(1000),
  }),
  params: z.object({ transactionId: identifier }),
  query: z.object({}),
});

export type CreateExchangeInput = z.infer<typeof exchangeEnvelopeSchema>;
