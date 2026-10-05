import { Schema, model, type HydratedDocument, type Model } from 'mongoose';
import type { TrustPassRecord } from './trust-pass.types.js';

export type TrustPassDocument = HydratedDocument<TrustPassRecord>;
export type TrustPassModelType = Model<TrustPassRecord>;

const trustPassSchema = new Schema<TrustPassRecord>(
  {
    passId: { type: String, required: true, unique: true, index: true },
    transactionId: { type: String, required: true, unique: true, index: true },
    decision: { type: String, required: true, enum: ['ALLOW'] },
    trustScore: { type: Number, required: true },
    payloadHash: { type: String, required: true },
    evidenceDigest: { type: String, required: true },
    policyVersion: { type: String, required: true },
    audience: { type: String, required: true },
    purpose: { type: String, required: true },
    issuedAt: { type: String, required: true },
    expiresAt: { type: String, required: true },
    issuer: { type: String, required: true },
    keyId: { type: String, required: true },
    signature: { type: String, required: true },
    status: { type: String, required: true, enum: ['ACTIVE', 'REVOKED'], default: 'ACTIVE' },
  },
  { timestamps: true, versionKey: false },
);

export const TrustPassModel = model<TrustPassRecord, TrustPassModelType>(
  'TrustPass',
  trustPassSchema,
  'trustPasses',
);
