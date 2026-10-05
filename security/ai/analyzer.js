/**
 * TRUST-PASS AI Security Analyzer Facade
 *
 * Ingests deterministic security verification reports and risk assessments,
 * producing clear, explainable summaries and clinical response recommendations.
 *
 * PRINCIPLE: AI explains findings; it NEVER determines cryptographic truth.
 */

'use strict';

const { MockAIAdapter } = require('./adapters/mock');
const { GeminiAIAdapter } = require('./adapters/gemini');

const defaultMock = new MockAIAdapter();
const defaultGemini = new GeminiAIAdapter();

/**
 * Normalizes input from either verification + risk reports or direct attributes.
 * @param {Object} input
 * @returns {Object} Normalized analysis input.
 */
function normalizeInput(input) {
  if (!input || typeof input !== 'object') {
    return {
      integrityValid: false,
      signatureValid: false,
      sourceKnown: false,
      riskScore: 75,
      severity: 'HIGH',
      findings: ['Missing verification report or input']
    };
  }

  // Case A: Combined object with verification and risk
  if (input.verification && input.risk) {
    return {
      integrityValid: Boolean(input.verification.integrityValid),
      signatureValid: Boolean(input.verification.signatureValid),
      sourceKnown: input.verification.sourceKnown !== false,
      riskScore: typeof input.risk.score === 'number' ? input.risk.score : 0,
      severity: input.risk.level || 'LOW',
      findings: input.risk.findings || input.verification.findings || [],
      clinicalPayload: input.verification.details?.payload || null
    };
  }

  // Case B: Raw verification report passed with score attached
  return {
    integrityValid: Boolean(input.integrityValid),
    signatureValid: Boolean(input.signatureValid),
    sourceKnown: input.sourceKnown !== false,
    riskScore: typeof input.riskScore === 'number' ? input.riskScore : (input.score || 0),
    severity: input.severity || input.level || 'LOW',
    findings: input.findings || [],
    clinicalPayload: input.clinicalPayload || null
  };
}

/**
 * Analyzes deterministic findings and provides human-readable clinical explanation.
 *
 * @param {Object} findingsInput Verification and risk findings.
 * @param {Object} [options]
 * @param {'mock'|'gemini'|Object} [options.adapter] Custom adapter instance or name.
 * @returns {Promise<{
 *   severity: string,
 *   riskScore: number,
 *   explanation: string,
 *   recommendation: string,
 *   findings: Array,
 *   provider: string,
 *   timestamp: string
 * }>}
 */
async function analyzeSecurityRisk(findingsInput, options = {}) {
  const normalized = normalizeInput(findingsInput);

  let adapter;
  if (options.adapter) {
    if (typeof options.adapter === 'object' && typeof options.adapter.generateAnalysis === 'function') {
      adapter = options.adapter;
    } else if (options.adapter === 'gemini') {
      adapter = defaultGemini;
    } else {
      adapter = defaultMock;
    }
  } else if (process.env.GEMINI_API_KEY || process.env.AI_API_KEY) {
    adapter = defaultGemini;
  } else {
    adapter = defaultMock;
  }

  const analysis = await adapter.generateAnalysis(normalized);

  return {
    severity: normalized.severity,
    riskScore: normalized.riskScore,
    explanation: analysis.explanation,
    recommendation: analysis.recommendation,
    findings: normalized.findings,
    provider: adapter.name || 'unknown',
    timestamp: new Date().toISOString()
  };
}

module.exports = {
  analyzeSecurityRisk,
  normalizeInput
};
