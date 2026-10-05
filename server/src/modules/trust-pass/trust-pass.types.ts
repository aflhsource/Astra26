export const trustPassStatuses = ['ACTIVE', 'REVOKED'] as const;
export type TrustPassStatus = (typeof trustPassStatuses)[number];

export interface TrustPassClaims {
  passId: string;
  transactionId: string;
  decision: 'ALLOW';
  trustScore: number;
  payloadHash: string;
  evidenceDigest: string;
  policyVersion: string;
  audience: string;
  purpose: string;
  issuedAt: string;
  expiresAt: string;
  issuer: 'TRUST-PASS-GATEWAY';
  keyId: string;
}

export interface TrustPassRecord extends TrustPassClaims {
  signature: string;
  status: TrustPassStatus;
  createdAt: Date;
  updatedAt: Date;
}
