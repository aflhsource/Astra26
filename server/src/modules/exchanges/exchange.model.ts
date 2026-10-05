import { Schema, model, type HydratedDocument, type Model } from 'mongoose';
import type { ExchangeRecord } from './exchange.types.js';

export type ExchangeDocument = HydratedDocument<ExchangeRecord>;
export type ExchangeModelType = Model<ExchangeRecord>;

const exchangeSchema = new Schema<ExchangeRecord>(
  {
    transactionId: { type: String, required: true, unique: true, index: true },
    source: {
      sourceId: { type: String, required: true },
      keyId: { type: String, required: true },
    },
    resourceType: { type: String, required: true },
    context: {
      patientRef: { type: String, required: true },
      encounterRef: { type: String, required: true },
      purpose: { type: String, required: true },
      audience: { type: String, required: true },
    },
    payload: {
      resourceType: { type: String, required: true },
      patientRef: { type: String, required: true },
      encounterRef: { type: String, required: true },
      data: { type: Schema.Types.Mixed, required: true },
    },
    issuedAt: { type: String, required: true },
    expiresAt: { type: String, required: true },
    sequence: { type: Number, required: true },
    nonce: { type: String, required: true },
    payloadHash: { type: String, required: true },
    provenance: {
      originSourceId: { type: String, required: true },
      originHash: { type: String, required: true },
      transformations: { type: [Schema.Types.Mixed], required: true },
    },
    signature: { type: String, required: true },
    verification: {
      decision: { type: String, required: true },
      reasonCodes: { type: [String], required: true },
      checks: {
        schemaValid: { type: Boolean, required: true },
        sourceKnown: { type: Boolean, required: true },
        keyKnown: { type: Boolean, required: true },
        hashValid: { type: Boolean, required: true },
        signatureValid: { type: Boolean, required: true },
        sourceActive: { type: Boolean, required: true },
        transactionUnique: { type: Boolean, required: true },
        nonceValid: { type: Boolean, required: true },
        sequenceValid: { type: Boolean, required: true },
        replayValid: { type: Boolean, required: true },
        freshnessValid: { type: Boolean, required: true },
      },
      sourceId: { type: String, required: true },
      keyId: { type: String, required: true },
      payloadHash: { type: String, required: true },
      verifiedAt: { type: String, required: true },
    },
  },
  { timestamps: true, versionKey: false },
);

exchangeSchema.index({ 'source.sourceId': 1 });
exchangeSchema.index({ 'source.sourceId': 1, nonce: 1 }, { unique: true });
exchangeSchema.index({ 'verification.decision': 1 });
exchangeSchema.index({ createdAt: -1 });

export const ExchangeModel = model<ExchangeRecord, ExchangeModelType>(
  'Exchange',
  exchangeSchema,
  'exchanges',
);
