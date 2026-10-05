/**
 * TRUST-PASS DOWNTIME-PASS: Cryptographically Signed Patient Safety Card
 *
 * Designed for hospital EHR outages, ransomware events, and offline disaster recovery.
 * Generates and validates self-contained, digitally signed patient safety cards
 * containing critical clinical information (allergies, medications, blood group).
 *
 * NOTE: MUST USE SYNTHETIC PATIENT DATA ONLY. NEVER USE REAL PATIENT DATA.
 */

'use strict';

const { hashData } = require('../crypto/hash');
const { signData, verifyData } = require('../crypto/sign');
const { computeKeyId } = require('../crypto/keys');

/**
 * Validates synthetic patient data structure.
 * @param {Object} patient
 */
function validateSyntheticPatientData(patient) {
  if (!patient || typeof patient !== 'object') {
    throw new TypeError('Patient data must be a non-null object');
  }
  if (!patient.patientId || typeof patient.patientId !== 'string') {
    throw new TypeError('Synthetic patientId is required (e.g. P-104)');
  }
  if (!patient.bloodGroup || typeof patient.bloodGroup !== 'string') {
    throw new TypeError('Synthetic bloodGroup is required (e.g. O+)');
  }
  if (!Array.isArray(patient.allergies)) {
    throw new TypeError('allergies must be an array of synthetic allergy strings');
  }
  if (!Array.isArray(patient.activeMedications)) {
    throw new TypeError('activeMedications must be an array of synthetic medication objects');
  }
}

/**
 * Creates a cryptographically signed patient safety card.
 *
 * @param {Object} patientData Synthetic patient clinical safety data.
 * @param {string} patientData.patientId Synthetic patient ID (e.g. 'P-104').
 * @param {string} patientData.bloodGroup Synthetic blood group (e.g. 'O+', 'A-').
 * @param {Array<string>} patientData.allergies List of documented allergies (e.g. ['Penicillin']).
 * @param {Array<{name: string, dose: string, frequency: string}>} patientData.activeMedications Active medications.
 * @param {Array<string>} [patientData.criticalConditions=[]] Critical alerts (e.g. ['Asthma', 'Diabetes']).
 * @param {string} privateKey Ed25519 private key in PEM format.
 * @param {Object} [options]
 * @param {string} [options.issuer='REGIONAL-HEALTHCARE-NETWORK'] Issuing authority name.
 * @param {string} [options.keyId] Public key fingerprint.
 * @param {string} [options.publicKey] Public key to auto-derive keyId.
 * @param {string} [options.issuedAt] Custom ISO timestamp.
 * @param {number} [options.validityDays=7] Validity window in days.
 * @returns {Object} Complete signed safety card ready for QR encoding or offline export.
 */
function createSafetyCard(patientData, privateKey, options = {}) {
  validateSyntheticPatientData(patientData);

  if (!privateKey) {
    throw new TypeError('Private key is required to sign safety card');
  }

  const issuedAt = options.issuedAt || new Date().toISOString();
  const validityDays = typeof options.validityDays === 'number' ? options.validityDays : 7;
  const issuedDate = new Date(issuedAt);
  const expiresAt = options.expiresAt || new Date(issuedDate.getTime() + validityDays * 24 * 60 * 60 * 1000).toISOString();

  let keyId = options.keyId;
  if (!keyId && options.publicKey) {
    keyId = computeKeyId(options.publicKey);
  }
  if (!keyId) {
    keyId = 'key-downtime-primary';
  }

  const cardId = `CARD-${patientData.patientId}-${hashData(issuedAt).substring(0, 8)}`;

  // Canonical clinical safety body
  const patient = {
    patientId: String(patientData.patientId).trim(),
    bloodGroup: String(patientData.bloodGroup).trim(),
    allergies: [...patientData.allergies],
    activeMedications: patientData.activeMedications.map(med => ({
      name: String(med.name).trim(),
      dose: String(med.dose).trim(),
      frequency: String(med.frequency).trim()
    })),
    criticalConditions: Array.isArray(patientData.criticalConditions) ? [...patientData.criticalConditions] : []
  };

  const issuer = options.issuer || 'REGIONAL-HEALTHCARE-NETWORK';

  // Digital signature binds the patient safety data, cardId, issuer, and validity dates
  const statementToSign = {
    cardId,
    issuer,
    issuedAt,
    expiresAt,
    version: 1,
    patient
  };

  const payloadHash = hashData(patient);
  const signResult = signData(statementToSign, privateKey, { keyId });

  return {
    cardId,
    issuer,
    issuedAt,
    expiresAt,
    version: 1,
    patient,
    integrity: {
      algorithm: 'SHA-256',
      hash: payloadHash,
      signatureAlgorithm: 'Ed25519',
      signature: signResult.signature,
      keyId
    }
  };
}

/**
 * Verifies a signed patient safety card.
 *
 * @param {Object} signedCard The signed safety card.
 * @param {string} publicKey Ed25519 public key in PEM format.
 * @param {Object} [options]
 * @param {boolean} [options.allowExpired=false] Whether expired cards are rejected or allowed with warning.
 * @returns {{
 *   valid: boolean,
 *   status: 'VALID'|'TAMPERED'|'EXPIRED'|'INVALID',
 *   reason: string,
 *   patient?: Object,
 *   issuer?: string,
 *   cardId?: string,
 *   keyId?: string,
 *   isExpired?: boolean
 * }}
 */
function verifySafetyCard(signedCard, publicKey, options = {}) {
  const result = {
    valid: false,
    status: 'INVALID',
    reason: ''
  };

  if (!signedCard || typeof signedCard !== 'object') {
    result.status = 'INVALID';
    result.reason = 'Missing or invalid safety card object';
    return result;
  }

  if (!publicKey) {
    result.status = 'INVALID';
    result.reason = 'Public verification key required';
    return result;
  }

  const { cardId, issuer, issuedAt, expiresAt, version, patient, integrity } = signedCard;

  if (!patient || !integrity || !integrity.signature || !integrity.hash) {
    result.status = 'TAMPERED';
    result.reason = 'Corrupted card envelope: missing clinical data or signature fields';
    return result;
  }

  // 1. Verify SHA-256 Digest of Patient Safety Data
  const computedHash = hashData(patient);
  if (computedHash !== integrity.hash) {
    result.status = 'TAMPERED';
    result.reason = 'Tamper detected: Patient safety data has been altered after issuance';
    return result;
  }

  // 2. Verify Digital Signature
  const statementToVerify = {
    cardId,
    issuer,
    issuedAt,
    expiresAt,
    version: version || 1,
    patient
  };

  const sigCheck = verifyData(statementToVerify, integrity.signature, publicKey);
  if (!sigCheck.valid) {
    result.status = 'TAMPERED';
    result.reason = 'Digital signature verification failed: Safety card is forged, modified, or signed by an unauthorized entity';
    return result;
  }

  // 3. Check Expiry
  const now = Date.now();
  const expiryTime = Date.parse(expiresAt);
  const isExpired = !isNaN(expiryTime) && now > expiryTime;

  if (isExpired && !options.allowExpired) {
    result.valid = false;
    result.status = 'EXPIRED';
    result.reason = `Safety card expired at ${expiresAt}`;
    result.patient = patient;
    result.isExpired = true;
    return result;
  }

  // Successful Verification
  result.valid = true;
  result.status = 'VALID';
  result.reason = 'Signature verified: Safety card authentic and intact';
  result.patient = patient;
  result.issuer = issuer;
  result.cardId = cardId;
  result.keyId = integrity.keyId;
  result.issuedAt = issuedAt;
  result.expiresAt = expiresAt;
  result.isExpired = isExpired;

  return result;
}

module.exports = {
  createSafetyCard,
  verifySafetyCard,
  validateSyntheticPatientData
};
