/**
 * TRUST-PASS Automated Tests: AI Security Analysis Layer (Phase 4)
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  analyzeSecurityRisk,
  MockAIAdapter,
  GeminiAIAdapter,
  buildAnalysisPrompt
} = require('../ai');
const { generateKeyPair } = require('../crypto');
const { createProvenanceRecord, verifyIntegrity } = require('../provenance');
const { calculateRiskScore } = require('../risk');

test('Phase 4: AI Security Analysis Layer', async (t) => {
  const ehrKeys = generateKeyPair();
  const clinicalPayload = {
    patientId: 'P-104',
    medication: 'Amoxicillin',
    dose: '500 mg',
    frequency: '3/day'
  };

  await t.test('generates clinical reassurance for authentic LOW risk record (Demo 1)', async () => {
    const record = createProvenanceRecord(
      clinicalPayload,
      { type: 'EHR', id: 'demo-ehr-01' },
      ehrKeys.privateKey,
      { publicKey: ehrKeys.publicKey }
    );

    const verification = verifyIntegrity(record, ehrKeys.publicKey);
    const risk = calculateRiskScore(verification);

    const analysis = await analyzeSecurityRisk({ verification, risk });

    assert.strictEqual(analysis.severity, 'LOW');
    assert.strictEqual(analysis.riskScore, 0);
    assert.strictEqual(analysis.provider, 'mock');
    assert.ok(analysis.explanation.includes('verified as authentic, intact'));
    assert.ok(analysis.recommendation.includes('Proceed with normal clinical workflows'));
    assert.ok(analysis.timestamp);
  });

  await t.test('generates actionable alert for tampered record (Demo 2: Modified Dose)', async () => {
    const record = createProvenanceRecord(
      clinicalPayload,
      { type: 'EHR', id: 'demo-ehr-01' },
      ehrKeys.privateKey,
      { publicKey: ehrKeys.publicKey }
    );

    // Tampered payload
    const tampered = {
      ...record,
      payload: { ...record.payload, dose: '5000 mg' }
    };

    const verification = verifyIntegrity(tampered, ehrKeys.publicKey);
    const risk = calculateRiskScore(verification);

    const analysis = await analyzeSecurityRisk({ verification, risk });

    assert.strictEqual(analysis.severity, 'CRITICAL');
    assert.ok(analysis.riskScore >= 85);
    assert.ok(analysis.explanation.includes('clinical payload no longer matches the signed version'));
    assert.ok(analysis.recommendation.includes('Do not trust the modified record'));
    assert.ok(analysis.recommendation.includes('Quarantine'));
  });

  await t.test('explains cryptographic signature failure as critical threat', async () => {
    const input = {
      integrityValid: true,
      signatureValid: false,
      sourceKnown: true,
      riskScore: 90,
      severity: 'CRITICAL',
      findings: ['Signature verification failed for keyId: key-unknown']
    };

    const analysis = await analyzeSecurityRisk(input);

    assert.strictEqual(analysis.severity, 'CRITICAL');
    assert.ok(analysis.explanation.includes('digital signature cannot be verified'));
    assert.ok(analysis.recommendation.includes('Reject the record'));
  });

  await t.test('explains untrusted origin source as high risk quarantine', async () => {
    const input = {
      integrityValid: true,
      signatureValid: true,
      sourceKnown: false,
      riskScore: 65,
      severity: 'HIGH',
      findings: ['Origin system not in approved registry']
    };

    const analysis = await analyzeSecurityRisk(input);

    assert.strictEqual(analysis.severity, 'HIGH');
    assert.ok(analysis.explanation.includes('not listed in the trusted healthcare authority directory'));
    assert.ok(analysis.recommendation.includes('quarantined triage queue'));
  });

  await t.test('builds strict prompt template maintaining cryptographic dominance', () => {
    const prompt = buildAnalysisPrompt({
      integrityValid: false,
      signatureValid: false,
      sourceKnown: true,
      riskScore: 95,
      severity: 'CRITICAL',
      findings: ['SHA-256 digest mismatch']
    });

    assert.ok(prompt.includes('NO (Payload tampered)'));
    assert.ok(prompt.includes('NO (Signature invalid)'));
    assert.ok(prompt.includes('Risk Score: 95 / 100'));
  });

  await t.test('Gemini adapter falls back cleanly to mock without API key', async () => {
    const geminiAdapter = new GeminiAIAdapter({ apiKey: '' });
    assert.strictEqual(geminiAdapter.apiKey, '');

    const result = await geminiAdapter.generateAnalysis({
      integrityValid: false,
      signatureValid: false,
      riskScore: 95,
      severity: 'CRITICAL'
    });

    assert.ok(result.explanation);
    assert.ok(result.recommendation);
  });

  await t.test('supports custom mock adapter override', async () => {
    const customAdapter = {
      name: 'custom-clinical-mock',
      async generateAnalysis(input) {
        return {
          explanation: `Custom analysis for score ${input.riskScore}`,
          recommendation: 'Custom action plan'
        };
      }
    };

    const analysis = await analyzeSecurityRisk(
      { integrityValid: true, signatureValid: true, riskScore: 0, severity: 'LOW' },
      { adapter: customAdapter }
    );

    assert.strictEqual(analysis.provider, 'custom-clinical-mock');
    assert.strictEqual(analysis.explanation, 'Custom analysis for score 0');
  });
});
