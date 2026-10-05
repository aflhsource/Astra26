import { randomUUID } from 'node:crypto';
import { sha256 } from '../crypto/hash.js';
import { sign, verify, fingerprintPublicKey } from '../crypto/signature.js';
import type { CryptoKey } from '../crypto/crypto.types.js';
import type { OfflineVerificationResult, SafetyCard, SafetyCardPatient } from './downtime.types.js';

const MAX_QR_PAYLOAD_LENGTH = 64 * 1024;
const QR_PREFIX = 'TP1.';

export function createSafetyCard(
  patient: SafetyCardPatient,
  privateKey: CryptoKey,
  publicKey: CryptoKey,
  options: { issuer?: string; issuedAt?: string; expiresAt?: string } = {},
): SafetyCard {
  validatePatient(patient);
  const issuedAt = options.issuedAt ?? new Date().toISOString();
  const expiresAt =
    options.expiresAt ?? new Date(Date.parse(issuedAt) + 7 * 86_400_000).toISOString();
  const normalizedPatient: SafetyCardPatient = {
    patientId: patient.patientId.trim(),
    bloodGroup: patient.bloodGroup.trim(),
    allergies: [...patient.allergies],
    activeMedications: patient.activeMedications.map((medication) => ({ ...medication })),
    criticalConditions: [...patient.criticalConditions],
  };
  const cardId = `CARD-${normalizedPatient.patientId}-${randomUUID()}`;
  const issuer = options.issuer ?? 'TRUST-PASS-DOWNTIME';
  const claims = {
    cardId,
    issuer,
    issuedAt,
    expiresAt,
    version: 1 as const,
    patient: normalizedPatient,
  };
  return {
    ...claims,
    integrity: {
      algorithm: 'SHA-256',
      hash: sha256(normalizedPatient),
      signatureAlgorithm: 'Ed25519',
      signature: sign(claims, privateKey),
      keyId: fingerprintPublicKey(publicKey),
    },
  };
}

export function verifySafetyCard(
  card: SafetyCard,
  publicKey: CryptoKey,
  now = Date.now(),
): OfflineVerificationResult {
  try {
    if (
      !card?.patient ||
      !card.integrity ||
      card.integrity.algorithm !== 'SHA-256' ||
      card.integrity.signatureAlgorithm !== 'Ed25519'
    )
      return invalid('Missing or invalid safety card envelope');
    if (sha256(card.patient) !== card.integrity.hash)
      return tampered('Safety card payload hash mismatch');
    const { integrity: _integrity, ...claims } = card;
    void _integrity;
    if (!verify(claims, card.integrity.signature, publicKey))
      return tampered('Safety card signature verification failed');
    const expiry = Date.parse(card.expiresAt);
    if (!Number.isFinite(expiry) || now >= expiry)
      return {
        valid: false,
        status: 'EXPIRED',
        offline: true,
        reason: 'Safety card is expired',
        patient: card.patient,
        cardId: card.cardId,
        issuer: card.issuer,
        keyId: card.integrity.keyId,
        isExpired: true,
      };
    return {
      valid: true,
      status: 'VALID',
      offline: true,
      reason: 'Safety card verified offline',
      patient: card.patient,
      cardId: card.cardId,
      issuer: card.issuer,
      keyId: card.integrity.keyId,
      isExpired: false,
    };
  } catch {
    return invalid('Safety card verification failed safely');
  }
}

export function encodeQrPayload(card: SafetyCard): string {
  const encoded = Buffer.from(JSON.stringify(card), 'utf8').toString('base64url');
  const result = `${QR_PREFIX}${encoded}`;
  if (Buffer.byteLength(result, 'utf8') > MAX_QR_PAYLOAD_LENGTH)
    throw new RangeError('QR payload exceeds 64KB maximum');
  return result;
}

export function decodeQrPayload(payload: string): SafetyCard {
  if (
    typeof payload !== 'string' ||
    payload.length > MAX_QR_PAYLOAD_LENGTH ||
    !payload.startsWith(QR_PREFIX)
  )
    throw new Error('Invalid or oversized TP1 payload');
  const card = JSON.parse(
    Buffer.from(payload.slice(QR_PREFIX.length), 'base64url').toString('utf8'),
  ) as SafetyCard;
  if (!card || typeof card !== 'object') throw new Error('TP1 payload is not an object');
  return card;
}

function validatePatient(patient: SafetyCardPatient): void {
  if (
    !patient.patientId ||
    !patient.bloodGroup ||
    !Array.isArray(patient.allergies) ||
    !Array.isArray(patient.activeMedications) ||
    !Array.isArray(patient.criticalConditions)
  )
    throw new TypeError('Synthetic safety card patient data is invalid');
}
function invalid(reason: string): OfflineVerificationResult {
  return { valid: false, status: 'INVALID', offline: true, reason };
}
function tampered(reason: string): OfflineVerificationResult {
  return { valid: false, status: 'TAMPERED', offline: true, reason };
}
