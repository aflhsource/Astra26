import { Schema, model, type HydratedDocument, type Model } from 'mongoose';
import type { AuditEventRecord } from './audit.types.js';

export type AuditEventDocument = HydratedDocument<AuditEventRecord>;
export type AuditEventModelType = Model<AuditEventRecord>;

const auditSchema = new Schema<AuditEventRecord>(
  {
    eventId: { type: String, required: true, unique: true },
    transactionId: String,
    eventType: { type: String, required: true },
    actorType: { type: String, required: true },
    actorId: { type: String, required: true },
    payloadHash: String,
    subjectRefHash: String,
    decision: String,
    reasonCodes: { type: [String], required: true },
    eventData: { type: Schema.Types.Mixed, required: true },
    previousEventHash: String,
    eventHash: { type: String, required: true },
    sequence: { type: Number, required: true },
    timestamp: { type: Date, required: true },
  },
  { versionKey: false },
);
auditSchema.index({ timestamp: 1 });
export const AuditEventModel = model<AuditEventRecord, AuditEventModelType>(
  'AuditEvent',
  auditSchema,
  'auditEvents',
);
