export type AuditActorType = 'SYSTEM' | 'SOURCE' | 'HUMAN' | 'DOWNSTREAM';

export interface AuditEventRecord {
  eventId: string;
  transactionId?: string;
  eventType: string;
  actorType: AuditActorType;
  actorId: string;
  payloadHash?: string;
  subjectRefHash?: string;
  decision?: string;
  reasonCodes: string[];
  eventData: Record<string, unknown>;
  previousEventHash?: string;
  eventHash: string;
  sequence: number;
  timestamp: Date;
}
