export const sourceRoles = ['SOURCE', 'TRANSFORMER', 'CONSUMER'] as const;
export type SourceRole = (typeof sourceRoles)[number];

export const sourceTypes = ['EHR', 'LAB', 'PHARMACY', 'INTEGRATION', 'CONSUMER'] as const;
export type SourceType = (typeof sourceTypes)[number];

export const sourceStatuses = ['ACTIVE', 'SUSPENDED', 'REVOKED'] as const;
export type SourceStatus = (typeof sourceStatuses)[number];

export interface SourceRecord {
  sourceId: string;
  name: string;
  role: SourceRole;
  type: SourceType;
  status: SourceStatus;
  keyId: string;
  publicKey: string;
  allowedTransformations: string[];
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateSourceInput {
  sourceId: string;
  name: string;
  role: SourceRole;
  type: SourceType;
  status: SourceStatus;
  keyId: string;
  publicKey: string;
  allowedTransformations: string[];
}
