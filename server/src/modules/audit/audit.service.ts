import { randomUUID } from 'node:crypto';
import { sha256 } from '../crypto/hash.js';
import { AuditEventModel } from './audit.model.js';
import type { AuditActorType, AuditEventRecord } from './audit.types.js';

export async function appendAuditEvent(
  input: Omit<AuditEventRecord, 'eventId' | 'eventHash' | 'sequence' | 'timestamp'>,
): Promise<void> {
  const previous = await AuditEventModel.findOne().sort({ sequence: -1 }).exec();
  const sequence = (previous?.sequence ?? 0) + 1;
  const event = {
    ...input,
    eventId: randomUUID(),
    sequence,
    timestamp: new Date(),
    ...(previous ? { previousEventHash: previous.eventHash } : {}),
  };
  const eventHash = sha256(event);
  await AuditEventModel.create({ ...event, eventHash });
}

export function systemAudit(
  transactionId: string,
  eventType: string,
  reasonCodes: string[],
  decision?: string,
  payloadHash?: string,
): Promise<void> {
  return appendAuditEvent({
    transactionId,
    eventType,
    actorType: 'SYSTEM' as AuditActorType,
    actorId: 'TRUST-PASS-GATEWAY',
    reasonCodes,
    eventData: {},
    ...(decision ? { decision } : {}),
    ...(payloadHash ? { payloadHash } : {}),
  });
}
