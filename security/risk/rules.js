/**
 * TRUST-PASS Deterministic Risk Rules & Severity Definitions
 *
 * NOTE: This is a hackathon cybersecurity prototype risk scoring engine.
 * Scores are explainable technical cyber-risk indicators and are NOT
 * medically validated clinical diagnostic scores.
 */

'use strict';

const RISK_LEVELS = {
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL'
};

const DISCLAIMER = 'Hackathon security prototype risk score. Not medically validated. Intended for technical cyber-risk assessment only.';

/**
 * Standard rule catalog with weights and severity classifications.
 */
const RULES = {
  INTEGRITY_FAILURE: {
    code: 'INTEGRITY_FAILURE',
    severity: RISK_LEVELS.CRITICAL,
    weight: 95,
    message: 'Clinical data payload altered after signing (SHA-256 digest mismatch)'
  },
  INVALID_SIGNATURE: {
    code: 'INVALID_SIGNATURE',
    severity: RISK_LEVELS.CRITICAL,
    weight: 90,
    message: 'Digital signature verification failed (tampered signature or unauthorized key)'
  },
  MISSING_PROVENANCE: {
    code: 'MISSING_PROVENANCE',
    severity: RISK_LEVELS.HIGH,
    weight: 75,
    message: 'Provenance metadata or cryptographic proof envelope is completely missing'
  },
  UNKNOWN_SOURCE: {
    code: 'UNKNOWN_SOURCE',
    severity: RISK_LEVELS.HIGH,
    weight: 65,
    message: 'Origin system identifier is unrecognized, unverified, or untrusted'
  },
  REPEATED_FAILURES: {
    code: 'REPEATED_FAILURES',
    severity: RISK_LEVELS.HIGH,
    weight: 60,
    message: 'Repeated verification failures detected from the same origin or IP'
  },
  UNEXPECTED_TRANSFORMATION: {
    code: 'UNEXPECTED_TRANSFORMATION',
    severity: RISK_LEVELS.MEDIUM,
    weight: 45,
    message: 'Unverified or unexpected transformation step recorded in record lineage'
  },
  SUSPICIOUS_VERSION: {
    code: 'SUSPICIOUS_VERSION',
    severity: RISK_LEVELS.MEDIUM,
    weight: 40,
    message: 'Non-sequential or unexpected version number in provenance header'
  },
  FUTURE_TIMESTAMP: {
    code: 'FUTURE_TIMESTAMP',
    severity: RISK_LEVELS.MEDIUM,
    weight: 40,
    message: 'Record creation timestamp is in the future (clock skew or tampering)'
  },
  STALE_TIMESTAMP: {
    code: 'STALE_TIMESTAMP',
    severity: RISK_LEVELS.MEDIUM,
    weight: 35,
    message: 'Record creation timestamp exceeds maximum allowable freshness window'
  }
};

/**
 * Maps a numeric score (0-100) to a categorical risk level.
 * @param {number} score Numeric score between 0 and 100.
 * @returns {'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'}
 */
function getRiskLevel(score) {
  if (score >= 85) return RISK_LEVELS.CRITICAL;
  if (score >= 60) return RISK_LEVELS.HIGH;
  if (score >= 30) return RISK_LEVELS.MEDIUM;
  return RISK_LEVELS.LOW;
}

module.exports = {
  RISK_LEVELS,
  RULES,
  DISCLAIMER,
  getRiskLevel
};
