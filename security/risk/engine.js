/**
 * TRUST-PASS Deterministic Risk Engine
 *
 * Evaluates cryptographic verification findings and context to compute
 * an explainable cybersecurity risk score and severity level.
 */

'use strict';

const { RULES, RISK_LEVELS, DISCLAIMER, getRiskLevel } = require('./rules');

/**
 * Computes a deterministic cybersecurity risk score from verification findings.
 *
 * @param {Object} verificationReport Result from verifyIntegrity or similar verifier.
 * @param {Object} [context] Optional operational context.
 * @param {number} [context.repeatedFailures=0] Count of consecutive failed verification attempts.
 * @param {boolean} [context.unexpectedTransformation=false] Flag for abnormal transformation.
 * @param {number} [context.expectedVersion] Expected sequence version.
 * @returns {{
 *   score: number,
 *   level: 'LOW'|'MEDIUM'|'HIGH'|'CRITICAL',
 *   findings: Array<{ code: string, severity: string, weight: number, message: string }>,
 *   summary: string,
 *   disclaimer: string
 * }}
 */
function calculateRiskScore(verificationReport, context = {}) {
  const triggeredFindings = [];

  // Edge case: null or invalid input
  if (!verificationReport || typeof verificationReport !== 'object') {
    triggeredFindings.push(RULES.MISSING_PROVENANCE);
    return {
      score: RULES.MISSING_PROVENANCE.weight,
      level: RISK_LEVELS.HIGH,
      findings: triggeredFindings,
      summary: 'Critical failure: Missing or unparseable verification input',
      disclaimer: DISCLAIMER
    };
  }

  // 1. Check Payload Integrity
  if (verificationReport.integrityValid === false) {
    triggeredFindings.push(RULES.INTEGRITY_FAILURE);
  }

  // 2. Check Digital Signature
  if (verificationReport.signatureValid === false) {
    triggeredFindings.push(RULES.INVALID_SIGNATURE);
  }

  // 3. Check Source Authenticity
  if (verificationReport.sourceKnown === false) {
    triggeredFindings.push(RULES.UNKNOWN_SOURCE);
  }

  // 4. Check Missing Provenance
  if (verificationReport.status === 'INVALID' && !verificationReport.details?.keyId) {
    if (!triggeredFindings.some(f => f.code === RULES.MISSING_PROVENANCE.code)) {
      triggeredFindings.push(RULES.MISSING_PROVENANCE);
    }
  }

  // 5. Inspect Findings for Timestamp & Lineage Flags
  const rawFindings = verificationReport.findings || [];
  for (const raw of rawFindings) {
    const text = String(raw).toLowerCase();
    if (text.includes('future')) {
      if (!triggeredFindings.some(f => f.code === RULES.FUTURE_TIMESTAMP.code)) {
        triggeredFindings.push(RULES.FUTURE_TIMESTAMP);
      }
    }
    if (text.includes('stale') || text.includes('max allowable age')) {
      if (!triggeredFindings.some(f => f.code === RULES.STALE_TIMESTAMP.code)) {
        triggeredFindings.push(RULES.STALE_TIMESTAMP);
      }
    }
    if (text.includes('missing from provenance') || text.includes('missing provenance')) {
      if (!triggeredFindings.some(f => f.code === RULES.MISSING_PROVENANCE.code)) {
        triggeredFindings.push(RULES.MISSING_PROVENANCE);
      }
    }
  }

  // 6. Contextual Factors
  if (context.repeatedFailures && context.repeatedFailures > 1) {
    triggeredFindings.push(RULES.REPEATED_FAILURES);
  }

  if (context.unexpectedTransformation === true) {
    triggeredFindings.push(RULES.UNEXPECTED_TRANSFORMATION);
  }

  if (context.expectedVersion && verificationReport.details?.version) {
    if (verificationReport.details.version !== context.expectedVersion) {
      triggeredFindings.push(RULES.SUSPICIOUS_VERSION);
    }
  }

  // Calculate Aggregate Score
  if (triggeredFindings.length === 0) {
    return {
      score: 0,
      level: RISK_LEVELS.LOW,
      findings: [],
      summary: 'All cryptographic and provenance checks passed. Data authentic and intact.',
      disclaimer: DISCLAIMER
    };
  }

  // Dominant factor scoring: Highest severity rule defines baseline, secondary rules compound
  const sortedWeights = triggeredFindings.map(f => f.weight).sort((a, b) => b - a);
  const maxWeight = sortedWeights[0];
  const secondarySum = sortedWeights.slice(1).reduce((acc, w) => acc + w, 0);

  const rawScore = maxWeight + Math.round(secondarySum * 0.12);
  const score = Math.min(100, Math.max(0, rawScore));
  const level = getRiskLevel(score);

  // Generate explainable summary
  const criticalCount = triggeredFindings.filter(f => f.severity === RISK_LEVELS.CRITICAL).length;
  const highCount = triggeredFindings.filter(f => f.severity === RISK_LEVELS.HIGH).length;
  const mediumCount = triggeredFindings.filter(f => f.severity === RISK_LEVELS.MEDIUM).length;

  let summaryParts = [];
  if (criticalCount > 0) summaryParts.push(`${criticalCount} critical`);
  if (highCount > 0) summaryParts.push(`${highCount} high`);
  if (mediumCount > 0) summaryParts.push(`${mediumCount} medium`);

  const summary = `Detected ${triggeredFindings.length} security anomaly finding(s) (${summaryParts.join(', ')}). Threat level: ${level}.`;

  return {
    score,
    level,
    findings: triggeredFindings,
    summary,
    disclaimer: DISCLAIMER
  };
}

module.exports = {
  calculateRiskScore
};
