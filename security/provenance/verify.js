/**
 * TRUST-PASS Deterministic Provenance & Integrity Verification
 *
 * Verifies that:
 * 1. The clinical payload hash matches its computed SHA-256 digest.
 * 2. The Ed25519 signature validates the payload hash and provenance statement.
 * 3. The origin source and audit trail are consistent.
 */

'use strict';

const { hashData } = require('../crypto/hash');
const { verifyHash } = require('../crypto/hash');
const { verifyData } = require('../crypto/sign');

/**
 * Deterministically verifies the cryptographic integrity and provenance of a record.
 *
 * @param {Object} record The record envelope { payload, provenance }.
 * @param {string} publicKey Ed25519 public key in PEM format.
 * @param {Object} [options]
 * @param {Array<string>} [options.trustedSources] Optional list of approved source IDs.
 * @param {number} [options.maxAgeMs] Optional maximum acceptable age in milliseconds.
 * @returns {Object} Structured verification report.
 */
function verifyIntegrity(record, publicKey, options = {}) {
  const report = {
    valid: false,
    status: 'INVALID',
    reason: '',
    integrityValid: false,
    signatureValid: false,
    sourceKnown: false,
    findings: [],
    details: {
      source: null,
      claimedHash: null,
      computedHash: null,
      keyId: null,
      version: null,
      createdAt: null
    }
  };

  // Guard: Validate record envelope structure
  if (!record || typeof record !== 'object') {
    report.reason = 'Missing or invalid record envelope';
    report.findings.push('Record must be a non-null object');
    return report;
  }

  const { payload, provenance } = record;

  if (!payload || typeof payload !== 'object') {
    report.reason = 'Missing clinical payload';
    report.findings.push('Payload is missing or not an object');
    return report;
  }

  if (!provenance || typeof provenance !== 'object' || !provenance.integrity) {
    report.reason = 'Missing provenance or integrity metadata';
    report.findings.push('Provenance metadata or integrity block is missing');
    return report;
  }

  const { integrity, source, createdAt, version, previousHash } = provenance;

  report.details.source = source || null;
  report.details.claimedHash = integrity.hash || null;
  report.details.keyId = integrity.keyId || null;
  report.details.version = version || 1;
  report.details.createdAt = createdAt || null;

  // Algorithm Whitelist Verification (Algorithm Confusion Defense)
  if (integrity.algorithm && integrity.algorithm !== 'SHA-256') {
    report.valid = false;
    report.status = 'UNSUPPORTED_ALGORITHM';
    report.reason = `Unsupported hash algorithm '${integrity.algorithm}'; only SHA-256 permitted`;
    report.findings.push(report.reason);
    return report;
  }

  if (integrity.signatureAlgorithm && integrity.signatureAlgorithm !== 'Ed25519') {
    report.valid = false;
    report.status = 'UNSUPPORTED_ALGORITHM';
    report.reason = `Unsupported signature algorithm '${integrity.signatureAlgorithm}'; only Ed25519 permitted`;
    report.findings.push(report.reason);
    return report;
  }

  // Step 1: Verify SHA-256 Payload Digest
  const computedHash = hashData(payload);
  report.details.computedHash = computedHash;

  const hashCheck = verifyHash(payload, integrity.hash);
  if (!hashCheck.valid) {
    report.integrityValid = false;
    report.status = 'INTEGRITY_FAILURE';
    report.reason = 'Payload integrity failure: clinical data modified after signing';
    report.findings.push(`Computed hash (${computedHash}) does not match claimed digest (${integrity.hash})`);
  } else {
    report.integrityValid = true;
  }

  // Step 2: Verify Ed25519 Asymmetric Digital Signature
  if (!publicKey) {
    report.signatureValid = false;
    report.status = 'VERIFICATION_ERROR';
    report.reason = 'Public key required for cryptographic signature verification';
    report.findings.push('Verification public key was not provided');
    return report;
  }

  const statementToVerify = {
    payloadHash: integrity.hash,
    source,
    createdAt,
    version,
    previousHash
  };

  const sigCheck = verifyData(statementToVerify, integrity.signature, publicKey);
  if (!sigCheck.valid) {
    report.signatureValid = false;
    if (report.status === 'INVALID') {
      report.status = 'INVALID_SIGNATURE';
      report.reason = 'Digital signature verification failed (tampered data, altered source, or wrong key)';
    }
    report.findings.push(`Signature invalid for keyId: ${integrity.keyId || 'unknown'}`);
  } else {
    report.signatureValid = true;
  }

  // Step 3: Source verification
  if (source && source.id) {
    if (options.trustedSources && Array.isArray(options.trustedSources)) {
      if (options.trustedSources.includes(source.id)) {
        report.sourceKnown = true;
      } else {
        report.sourceKnown = false;
        report.findings.push(`Source ID '${source.id}' is not in the trusted sources registry`);
      }
    } else {
      report.sourceKnown = true; // No whitelist enforced, source present
    }
  } else {
    report.sourceKnown = false;
    report.findings.push('Source identification missing from provenance');
  }

  // Step 4: Timestamp validation (stale or future timestamp)
  if (createdAt) {
    const createdTime = Date.parse(createdAt);
    const now = Date.now();

    if (isNaN(createdTime)) {
      report.findings.push('Invalid ISO-8601 creation timestamp in provenance');
    } else {
      // Future timestamp check (allowing 60s clock skew)
      if (createdTime > now + 60000) {
        report.findings.push('Anomaly: Record timestamp is in the future');
      }

      // Stale timestamp check if maxAgeMs is specified
      if (options.maxAgeMs && now - createdTime > options.maxAgeMs) {
        report.findings.push(`Record timestamp exceeds max allowable age (${options.maxAgeMs}ms)`);
      }
    }
  }

  // Final Overall Validity Determination
  if (report.integrityValid && report.signatureValid && report.findings.length === 0) {
    report.valid = true;
    report.status = 'VALID';
    report.reason = 'Data authentic, intact, and provenance verified';
  } else if (!report.integrityValid) {
    report.valid = false;
    report.status = 'INTEGRITY_FAILURE';
  } else if (!report.signatureValid) {
    report.valid = false;
    report.status = 'INVALID_SIGNATURE';
  } else {
    // Both crypto checks passed, but metadata policy failed (e.g. untrusted source or stale time)
    report.valid = false;
    report.status = 'POLICY_WARNING';
    report.reason = 'Cryptographic signature valid but policy violations detected';
  }

  return report;
}

module.exports = {
  verifyIntegrity
};
