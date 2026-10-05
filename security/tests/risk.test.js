/**
 * TRUST-PASS Automated Tests: Risk Engine (Phase 3)
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { generateKeyPair } = require('../crypto');
const { createProvenanceRecord, verifyIntegrity } = require('../provenance');
const { calculateRiskScore, RISK_LEVELS, RULES, getRiskLevel } = require('../risk');

test('Phase 3: Deterministic Security Risk Engine', async (t) => {
  const ehrKeys = generateKeyPair();
  const clinicalPayload = {
    patientId: 'P-104',
    medication: 'Amoxicillin',
    dose: '500 mg',
    frequency: '3/day'
  };

  await t.test('evaluates genuine verified record as LOW risk with 0 score (Demo 1)', () => {
    const record = createProvenanceRecord(
      clinicalPayload,
      { type: 'EHR', id: 'demo-ehr-01' },
      ehrKeys.privateKey,
      { publicKey: ehrKeys.publicKey }
    );

    const report = verifyIntegrity(record, ehrKeys.publicKey);
    const riskAssessment = calculateRiskScore(report);

    assert.strictEqual(riskAssessment.score, 0);
    assert.strictEqual(riskAssessment.level, RISK_LEVELS.LOW);
    assert.strictEqual(riskAssessment.findings.length, 0);
    assert.ok(riskAssessment.summary.includes('All cryptographic and provenance checks passed'));
    assert.ok(riskAssessment.disclaimer.includes('Not medically validated'));
  });

  await t.test('evaluates payload integrity failure as CRITICAL risk (Demo 2: Tampered Record)', () => {
    const record = createProvenanceRecord(
      clinicalPayload,
      { type: 'EHR', id: 'demo-ehr-01' },
      ehrKeys.privateKey,
      { publicKey: ehrKeys.publicKey }
    );

    // Tamper medication
    const tampered = {
      ...record,
      payload: { ...record.payload, dose: '5000 mg' }
    };

    const report = verifyIntegrity(tampered, ehrKeys.publicKey);
    const riskAssessment = calculateRiskScore(report);

    assert.ok(riskAssessment.score >= 85, `Expected score >= 85, got ${riskAssessment.score}`);
    assert.strictEqual(riskAssessment.level, RISK_LEVELS.CRITICAL);
    assert.ok(riskAssessment.findings.some(f => f.code === RULES.INTEGRITY_FAILURE.code));
    assert.ok(riskAssessment.summary.includes('critical'));
  });

  await t.test('evaluates invalid digital signature as CRITICAL risk', () => {
    const wrongKeys = generateKeyPair();
    const record = createProvenanceRecord(
      clinicalPayload,
      { type: 'EHR', id: 'demo-ehr-01' },
      ehrKeys.privateKey,
      { publicKey: ehrKeys.publicKey }
    );

    // Verify with mismatched key
    const report = verifyIntegrity(record, wrongKeys.publicKey);
    const riskAssessment = calculateRiskScore(report);

    assert.ok(riskAssessment.score >= 85);
    assert.strictEqual(riskAssessment.level, RISK_LEVELS.CRITICAL);
    assert.ok(riskAssessment.findings.some(f => f.code === RULES.INVALID_SIGNATURE.code));
  });

  await t.test('evaluates unknown or unapproved source as HIGH risk', () => {
    const record = createProvenanceRecord(
      clinicalPayload,
      { type: 'EHR', id: 'unauthorized-external-vendor' },
      ehrKeys.privateKey,
      { publicKey: ehrKeys.publicKey }
    );

    // Restrict to approved sources
    const report = verifyIntegrity(record, ehrKeys.publicKey, {
      trustedSources: ['demo-ehr-01', 'central-hospital-01']
    });

    const riskAssessment = calculateRiskScore(report);

    assert.ok(riskAssessment.score >= 60 && riskAssessment.score < 85);
    assert.strictEqual(riskAssessment.level, RISK_LEVELS.HIGH);
    assert.ok(riskAssessment.findings.some(f => f.code === RULES.UNKNOWN_SOURCE.code));
  });

  await t.test('evaluates timestamp anomalies as MEDIUM risk', () => {
    const mockReport = {
      valid: false,
      integrityValid: true,
      signatureValid: true,
      sourceKnown: true,
      findings: ['Record timestamp exceeds max allowable age (3600000ms)']
    };

    const riskAssessment = calculateRiskScore(mockReport);
    assert.strictEqual(riskAssessment.level, RISK_LEVELS.MEDIUM);
    assert.ok(riskAssessment.findings.some(f => f.code === RULES.STALE_TIMESTAMP.code));
  });

  await t.test('compounds multiple threats and caps accurately at 100', () => {
    const mockMultiThreatReport = {
      valid: false,
      integrityValid: false, // 95 (CRITICAL)
      signatureValid: false, // 90 (CRITICAL)
      sourceKnown: false,    // 65 (HIGH)
      findings: ['Record timestamp is in the future'] // 40 (MEDIUM)
    };

    const riskAssessment = calculateRiskScore(mockMultiThreatReport, {
      repeatedFailures: 5, // 60 (HIGH)
      unexpectedTransformation: true // 45 (MEDIUM)
    });

    assert.strictEqual(riskAssessment.score, 100);
    assert.strictEqual(riskAssessment.level, RISK_LEVELS.CRITICAL);
    assert.ok(riskAssessment.findings.length >= 4);
  });

  await t.test('safely handles null or malformed report input', () => {
    const riskAssessment = calculateRiskScore(null);
    assert.strictEqual(riskAssessment.level, RISK_LEVELS.HIGH);
    assert.ok(riskAssessment.findings.some(f => f.code === RULES.MISSING_PROVENANCE.code));
  });

  await t.test('accurately maps score boundaries with getRiskLevel', () => {
    assert.strictEqual(getRiskLevel(0), RISK_LEVELS.LOW);
    assert.strictEqual(getRiskLevel(29), RISK_LEVELS.LOW);
    assert.strictEqual(getRiskLevel(30), RISK_LEVELS.MEDIUM);
    assert.strictEqual(getRiskLevel(59), RISK_LEVELS.MEDIUM);
    assert.strictEqual(getRiskLevel(60), RISK_LEVELS.HIGH);
    assert.strictEqual(getRiskLevel(84), RISK_LEVELS.HIGH);
    assert.strictEqual(getRiskLevel(85), RISK_LEVELS.CRITICAL);
    assert.strictEqual(getRiskLevel(100), RISK_LEVELS.CRITICAL);
  });
});
