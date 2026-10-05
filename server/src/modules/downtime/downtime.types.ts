export interface SafetyCardPatient {
  patientId: string;
  bloodGroup: string;
  allergies: string[];
  activeMedications: Array<{ name: string; dose: string; frequency: string }>;
  criticalConditions: string[];
}

export interface SafetyCard {
  cardId: string;
  issuer: string;
  issuedAt: string;
  expiresAt: string;
  version: 1;
  patient: SafetyCardPatient;
  integrity: {
    algorithm: 'SHA-256';
    hash: string;
    signatureAlgorithm: 'Ed25519';
    signature: string;
    keyId: string;
  };
}

export interface OfflineVerificationResult {
  valid: boolean;
  status: 'VALID' | 'TAMPERED' | 'EXPIRED' | 'INVALID';
  offline: true;
  reason: string;
  patient?: SafetyCardPatient;
  issuer?: string;
  cardId?: string;
  keyId?: string;
  isExpired?: boolean;
}
