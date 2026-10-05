/**
 * TRUST-PASS Provenance & Integrity Model
 *
 * Constructs standardized provenance envelopes that bind clinical data
 * to its originating source, timestamp, version, audit transformations,
 * SHA-256 digest, and Ed25519 asymmetric signature.
 */

'use strict';

const { hashData } = require('../crypto/hash');
const { signData } = require('../crypto/sign');
const { computeKeyId } = require('../crypto/keys');

/**
 * Creates a signed provenance record wrapping clinical payload data.
 *
 * @param {Object} payload The clinical payload (e.g. medication, vitals, patient data).
 * @param {Object} [sourceInfo] Information about the issuing system.
 * @param {string} [sourceInfo.type='EHR'] System type (EHR, CLINIC, LAB, PHARMACY).
 * @param {string} [sourceInfo.id='demo-ehr-01'] System unique identifier.
 * @param {string} privateKey Ed25519 private key in PEM format.
 * @param {Object} [options]
 * @param {string} [options.keyId] Optional explicit key identifier (computed if omitted).
 * @param {string} [options.publicKey] Optional public key used to compute keyId.
 * @param {number} [options.version=1] Data version number.
 * @param {Array<Object>} [options.transformations=[]] Recorded audit transformations.
 * @param {string|null} [options.previousHash=null] Hash of predecessor record (for audit chains).
 * @param {string} [options.createdAt] ISO 8601 creation timestamp.
 * @returns {{ payload: Object, provenance: Object }} The complete signed record envelope.
 */
function createProvenanceRecord(payload, sourceInfo, privateKey, options = {}) {
  if (!payload || typeof payload !== 'object') {
    throw new TypeError('Payload must be a non-null object');
  }
  if (!privateKey) {
    throw new TypeError('Private key is required to sign provenance record');
  }

  const source = {
    type: (sourceInfo && sourceInfo.type) || 'EHR',
    id: (sourceInfo && sourceInfo.id) || 'demo-ehr-01'
  };

  const createdAt = options.createdAt || new Date().toISOString();
  const version = typeof options.version === 'number' ? options.version : 1;
  const transformations = Array.isArray(options.transformations) ? [...options.transformations] : [];
  const previousHash = options.previousHash || null;

  // Step 1: Compute SHA-256 digest of the clinical payload
  const currentHash = hashData(payload);

  // Step 2: Resolve keyId
  let keyId = options.keyId;
  if (!keyId && options.publicKey) {
    keyId = computeKeyId(options.publicKey);
  }
  if (!keyId) {
    keyId = 'key-ehr-primary';
  }

  // Step 3: Build the signed statement binding payload digest to source, time, and version
  const statementToSign = {
    payloadHash: currentHash,
    source,
    createdAt,
    version,
    previousHash
  };

  // Step 4: Digitally sign the statement with Ed25519
  const signResult = signData(statementToSign, privateKey, { keyId });

  const provenance = {
    source,
    createdAt,
    version,
    transformations,
    previousHash,
    integrity: {
      algorithm: 'SHA-256',
      hash: currentHash,
      signatureAlgorithm: 'Ed25519',
      signature: signResult.signature,
      keyId
    }
  };

  return {
    payload,
    provenance
  };
}

/**
 * Records an authorized transformation on a record and updates its audit trail.
 *
 * @param {{ payload: Object, provenance: Object }} record Existing record envelope.
 * @param {Object} transformation Details of the transformation.
 * @param {string} transformation.system System performing transformation.
 * @param {string} transformation.action Action description (e.g. 'UNIT_CONVERSION').
 * @param {Object} [transformation.details] Optional extra metadata.
 * @param {Object} [newPayload] Modified payload if data changed.
 * @param {string} privateKey Private key of the transforming system.
 * @param {Object} [options]
 * @returns {{ payload: Object, provenance: Object }} Updated record envelope.
 */
function appendTransformation(record, transformation, newPayload, privateKey, options = {}) {
  if (!record || !record.provenance || !record.payload) {
    throw new TypeError('Invalid record format: must contain payload and provenance');
  }
  if (!privateKey) {
    throw new TypeError('Private key is required to sign transformed record');
  }

  const payload = newPayload || record.payload;
  const previousHash = record.provenance.integrity.hash;
  const currentHash = hashData(payload);

  const transformationEntry = {
    system: transformation.system || 'INTERMEDIARY',
    action: transformation.action || 'MODIFY',
    timestamp: transformation.timestamp || new Date().toISOString(),
    details: transformation.details || {},
    priorHash: previousHash,
    resultingHash: currentHash
  };

  const updatedTransformations = [...(record.provenance.transformations || []), transformationEntry];
  const newVersion = (record.provenance.version || 1) + 1;

  return createProvenanceRecord(
    payload,
    record.provenance.source,
    privateKey,
    {
      ...options,
      version: newVersion,
      previousHash,
      transformations: updatedTransformations,
      keyId: options.keyId || record.provenance.integrity.keyId
    }
  );
}

module.exports = {
  createProvenanceRecord,
  appendTransformation
};
