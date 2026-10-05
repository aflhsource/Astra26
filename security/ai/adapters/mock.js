/**
 * TRUST-PASS Deterministic AI Mock Adapter
 *
 * Provides instant, zero-dependency, deterministic explanations and clinical
 * recommendations without requiring external network connectivity or API keys.
 * Used for local development, offline operations, and testing.
 */

'use strict';

class MockAIAdapter {
  constructor() {
    this.name = 'mock';
  }

  /**
   * Generates a deterministic explanation and recommendation.
   * @param {Object} input
   * @param {boolean} input.integrityValid
   * @param {boolean} input.signatureValid
   * @param {boolean} [input.sourceKnown]
   * @param {number} input.riskScore
   * @param {'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'} input.severity
   * @param {Array<Object|string>} input.findings
   * @returns {Promise<{ explanation: string, recommendation: string }>}
   */
  async generateAnalysis(input) {
    const { integrityValid, signatureValid, sourceKnown, severity, findings = [] } = input;

    // Check for Critical Integrity Failure (Tampered Data)
    if (!integrityValid) {
      return {
        explanation: 'The clinical payload no longer matches the signed version. Critical clinical data (such as medication, dosage, or laboratory values) has been altered after it was cryptographically issued.',
        recommendation: 'Do not trust the modified record. Do not administer medications or execute treatments based on this payload. Quarantine the record immediately, verify directly with the authoritative clinician, and inspect intermediate integrations.'
      };
    }

    // Check for Critical Signature Failure (Forged or Corrupted)
    if (!signatureValid) {
      return {
        explanation: 'The cryptographic digital signature cannot be verified against the trusted public key. The record may have originated from an unverified actor, or the signature envelope was corrupted in transit.',
        recommendation: 'Reject the record. Request a fresh, cryptographically signed transmission from the verified healthcare authority and inspect the transmitting endpoint for compromise.'
      };
    }

    // Check for Unknown / Untrusted Source
    if (sourceKnown === false) {
      return {
        explanation: 'The originating system identifier is not listed in the trusted healthcare authority directory. While cryptographic proofs are technically valid, the issuing entity lacks established institutional trust.',
        recommendation: 'Hold the data in a quarantined triage queue. Verify organizational authorization before importing records into the local EHR.'
      };
    }

    // Check for Lineage / Timestamp Anomalies (Medium Risk)
    if (severity === 'MEDIUM') {
      return {
        explanation: 'Provenance anomalies detected in the transmission metadata (such as significant timestamp drift, future-dating, or unverified intermediary transformation).',
        recommendation: 'Review the audit log and check network clock synchronization (NTP) before relying on time-sensitive clinical actions.'
      };
    }

    // Default: Authenticated Low Risk Record
    return {
      explanation: 'The clinical payload has been verified as authentic, intact, and originating from a recognized healthcare system with full cryptographic non-repudiation.',
      recommendation: 'Proceed with normal clinical workflows. No security or integrity risks detected.'
    };
  }
}

module.exports = {
  MockAIAdapter
};
