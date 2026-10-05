import { Schema, model, type HydratedDocument, type Model } from 'mongoose';
import type {
  CreateSourceInput,
  SourceRecord,
  SourceRole,
  SourceStatus,
  SourceType,
} from './source.types.js';

export type SourceDocument = HydratedDocument<SourceRecord>;
export type SourceModelType = Model<SourceRecord>;

const sourceSchema = new Schema<SourceRecord>(
  {
    sourceId: { type: String, required: true, unique: true, index: true, trim: true },
    name: { type: String, required: true, trim: true },
    role: {
      type: String,
      required: true,
      enum: ['SOURCE', 'TRANSFORMER', 'CONSUMER'] satisfies SourceRole[],
    },
    type: {
      type: String,
      required: true,
      enum: ['EHR', 'LAB', 'PHARMACY', 'INTEGRATION', 'CONSUMER'] satisfies SourceType[],
    },
    status: {
      type: String,
      required: true,
      enum: ['ACTIVE', 'SUSPENDED', 'REVOKED'] satisfies SourceStatus[],
    },
    keyId: { type: String, required: true, index: true, trim: true },
    publicKey: { type: String, required: true },
    allowedTransformations: { type: [String], required: true, default: [] },
  },
  { timestamps: true, versionKey: false },
);

sourceSchema.index({ sourceId: 1, keyId: 1 }, { unique: true });

export const SourceModel = model<SourceRecord, SourceModelType>('Source', sourceSchema, 'sources');

export function toCreateSourceInput(document: SourceDocument): CreateSourceInput {
  return {
    sourceId: document.sourceId,
    name: document.name,
    role: document.role,
    type: document.type,
    status: document.status,
    keyId: document.keyId,
    publicKey: document.publicKey,
    allowedTransformations: [...document.allowedTransformations],
  };
}
