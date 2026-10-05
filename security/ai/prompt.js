/**
 * TRUST-PASS AI Security Analysis Prompt Templates
 *
 * Strict prompt constraints ensuring AI operates exclusively as an explainability
 * layer and cannot override deterministic cryptographic findings.
 */

'use strict';

const SYSTEM_PROMPT = `You are the TRUST-PASS Healthcare Cybersecurity Intelligence Engine.
Your role is to explain deterministic cryptographic verification findings to healthcare clinical staff and incident responders.

CRITICAL SECURITY RULES:
1. You are NOT the cryptographic verifier. The deterministic cryptographic engine has ALREADY decided validity and risk score.
2. You MUST NOT declare a tampered or invalid payload as safe or authentic under ANY circumstances.
3. Be direct, concise, and clinically actionable.
4. Distinguish between patient safety risks (e.g. modified medication dosage) and administrative risks (e.g. stale timestamp).
5. Output valid JSON matching the exact requested schema:
{
  "explanation": "concise explanation of what was detected and potential clinical impact",
  "recommendation": "immediate actionable clinical or security steps to take"
}`;

/**
 * Builds the structured user prompt from deterministic security findings.
 * @param {Object} input
 * @param {boolean} input.integrityValid
 * @param {boolean} input.signatureValid
 * @param {boolean} [input.sourceKnown]
 * @param {number} input.riskScore
 * @param {'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'} input.severity
 * @param {Array<string|Object>} input.findings
 * @param {Object} [input.clinicalContext]
 * @returns {string} Formatted prompt string.
 */
function buildAnalysisPrompt(input) {
  const findingsList = (input.findings || []).map((f, i) => {
    if (typeof f === 'string') return `${i + 1}. ${f}`;
    return `${i + 1}. [${f.code || 'ANOMALY'}] ${f.message || JSON.stringify(f)}`;
  }).join('\n');

  return `Deterministic Security Verification Findings:
- Integrity Valid: ${input.integrityValid ? 'YES (SHA-256 matched)' : 'NO (Payload tampered)'}
- Signature Valid: ${input.signatureValid ? 'YES (Authentic Ed25519 signature)' : 'NO (Signature invalid)'}
- Source Known: ${input.sourceKnown !== false ? 'YES' : 'NO (Untrusted or missing origin)'}
- Risk Score: ${input.riskScore} / 100
- Severity Level: ${input.severity}

Specific Findings:
${findingsList || 'None (All cryptographic checks passed)'}

${input.clinicalContext ? `Clinical Payload Context: ${JSON.stringify(input.clinicalContext)}` : ''}

Provide a concise Explanation and actionable Recommendation in JSON format.`;
}

module.exports = {
  SYSTEM_PROMPT,
  buildAnalysisPrompt
};
