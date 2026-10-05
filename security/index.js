/**
 * TRUST-PASS & DOWNTIME-PASS Security Module
 * Core Security, Cryptographic Integrity, Provenance & Offline Verification Layer
 */

'use strict';

const crypto = require('./crypto');
const provenance = require('./provenance');
const risk = require('./risk');
const downtime = require('./downtime');

module.exports = {
  // Phase 1: Cryptographic Foundation
  canonicalize: crypto.canonicalize,
  hashData: crypto.hashData,
  verifyHash: crypto.verifyHash,
  generateKeyPair: crypto.generateKeyPair,
  computeKeyId: crypto.computeKeyId,
  signData: crypto.signData,
  verifyData: crypto.verifyData,

  // Phase 2: Provenance + Integrity
  createProvenanceRecord: provenance.createProvenanceRecord,
  appendTransformation: provenance.appendTransformation,
  verifyIntegrity: provenance.verifyIntegrity,

  // Phase 3: Risk Engine
  calculateRiskScore: risk.calculateRiskScore,
  getRiskLevel: risk.getRiskLevel,
  RISK_LEVELS: risk.RISK_LEVELS,
  RULES: risk.RULES,

  // Phase 4 & 5: DOWNTIME-PASS & Offline Verification
  createSafetyCard: downtime.createSafetyCard,
  verifySafetyCard: downtime.verifySafetyCard,
  verifySafetyCardLocally: downtime.verifySafetyCardLocally,
  encodeQRPayload: downtime.encodeQRPayload,
  decodeQRPayload: downtime.decodeQRPayload,

  // Namespace exports
  crypto,
  provenance,
  risk,
  downtime
};
