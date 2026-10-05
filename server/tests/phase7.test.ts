import { describe, expect, it } from 'vitest';
import { generateEd25519KeyPair } from '../src/modules/crypto/signature.js';
import { canonicalize } from '../src/modules/crypto/canonicalize.js';
import { sha256, verifySha256 } from '../src/modules/crypto/hash.js';
import { sign, verify } from '../src/modules/crypto/signature.js';
import {
  createSafetyCard,
  decodeQrPayload,
  encodeQrPayload,
  verifySafetyCard,
} from '../src/modules/downtime/downtime.service.js';
import { analyzeSecurityEvidence } from '../src/modules/trust/security-analyzer.js';
import { validateContext } from '../src/modules/context/context.service.js';
import { calculateTrustScore, evaluatePolicy } from '../src/modules/trust/trust.engine.js';
import { resourceRisk } from '../src/modules/trust/trust.types.js';
import type {
  ExchangeEnvelope,
  VerificationChecks,
} from '../src/modules/exchanges/exchange.types.js';

const checks = (overrides: Partial<VerificationChecks> = {}): VerificationChecks => ({
  schemaValid: true,
  sourceKnown: true,
  keyKnown: true,
  hashValid: true,
  signatureValid: true,
  sourceActive: true,
  transactionUnique: true,
  nonceValid: true,
  sequenceValid: true,
  replayValid: true,
  freshnessValid: true,
  provenanceValid: true,
  contextValid: true,
  ...overrides,
});

const exchange = (overrides: Partial<ExchangeEnvelope> = {}): ExchangeEnvelope => ({
  transactionId: 'TX-P7-001',
  source: { sourceId: 'LAB-A', keyId: 'lab-a-key-1' },
  resourceType: 'Observation',
  context: {
    patientRef: 'PAT-1001',
    encounterRef: 'ENC-1001',
    purpose: 'clinical-decision-support',
    audience: 'CLINICAL-CONSUMER',
  },
  payload: {
    resourceType: 'Observation',
    patientRef: 'PAT-1001',
    encounterRef: 'ENC-1001',
    data: {},
  },
  issuedAt: '2026-10-05T12:00:00.000Z',
  expiresAt: '2026-10-05T12:05:00.000Z',
  sequence: 1,
  nonce: 'nonce-p7',
  payloadHash: 'a'.repeat(64),
  provenance: { originSourceId: 'LAB-A', originHash: 'a'.repeat(64), transformations: [] },
  signature: 'signature',
  ...overrides,
});

describe('Phase 7 trust decision layer', () => {
  it('validates matching context and rejects patient/encounter mismatch', () => {
    expect(validateContext(exchange()).valid).toBe(true);
    expect(
      validateContext(exchange({ context: { ...exchange().context, patientRef: 'PAT-9999' } }))
        .reasonCodes,
    ).toContain('CONTEXT_MISMATCH');
    expect(
      validateContext(exchange({ payload: { ...exchange().payload, encounterRef: 'ENC-9999' } }))
        .valid,
    ).toBe(false);
  });

  it('classifies resource security impact explicitly', () => {
    expect(resourceRisk.Observation).toBe('HIGH');
    expect(resourceRisk.MedicationRequest).toBe('CRITICAL');
    expect(resourceRisk.AllergyIntolerance).toBe('CRITICAL');
    expect(resourceRisk.DiagnosticReport).toBe('HIGH');
    expect(resourceRisk.DemographicUpdate).toBe('MEDIUM');
  });

  it('scores clean evidence at 100 and policy allows it', () => {
    const assessment = analyzeSecurityEvidence({
      checks: checks(),
      reasonCodes: [],
      resourceRisk: 'HIGH',
    });
    const score = calculateTrustScore({ checks: checks(), securityAssessment: assessment });
    expect(score.score).toBe(100);
    expect(
      evaluatePolicy({
        checks: checks(),
        securityAssessment: assessment,
        score: score.score,
        reasonCodes: [],
        resourceRisk: 'HIGH',
      }).decision,
    ).toBe('ALLOW');
  });

  it('keeps context anomalies in review and hard failures quarantined', () => {
    const assessment = analyzeSecurityEvidence({
      checks: checks({ contextValid: false }),
      reasonCodes: ['CONTEXT_MISMATCH'],
      resourceRisk: 'HIGH',
    });
    const score = calculateTrustScore({
      checks: checks({ contextValid: false }),
      securityAssessment: assessment,
    });
    expect(
      evaluatePolicy({
        checks: checks({ contextValid: false }),
        securityAssessment: assessment,
        score: score.score,
        reasonCodes: ['CONTEXT_MISMATCH'],
        resourceRisk: 'HIGH',
      }).decision,
    ).toBe('REVIEW');
    expect(
      evaluatePolicy({
        checks: checks(),
        securityAssessment: assessment,
        score: 100,
        reasonCodes: ['INVALID_SIGNATURE'],
        resourceRisk: 'HIGH',
      }).decision,
    ).toBe('QUARANTINE');
  });

  it('keeps deterministic security assessment output bounded', () => {
    const assessment = analyzeSecurityEvidence({
      checks: checks({ contextValid: false }),
      reasonCodes: ['CONTEXT_MISMATCH'],
      resourceRisk: 'HIGH',
    });
    expect(assessment.anomalyScore).toBeGreaterThanOrEqual(0);
    expect(assessment.anomalyScore).toBeLessThanOrEqual(100);
    expect(assessment.recommendation).toBe('ALLOW');
  });

  it('hardens canonicalization, hash comparison, and Ed25519 signature parsing', () => {
    let bomb: Record<string, unknown> = { leaf: true };
    for (let index = 0; index < 80; index += 1) bomb = { nested: bomb };
    expect(() => canonicalize(bomb)).toThrow('depth bomb defense');
    const value = { synthetic: true };
    const digest = sha256(value);
    expect(verifySha256(value, digest.toUpperCase())).toBe(true);
    const keys = generateEd25519KeyPair();
    const signature = sign(value, keys.privateKey);
    expect(verify(value, signature.slice(0, -1), keys.publicKey)).toBe(false);
    expect(verify(value, `${signature}=`, keys.publicKey)).toBe(false);
  });

  it('creates and verifies a bounded TP1 DOWNTIME-PASS offline card', () => {
    const keys = generateEd25519KeyPair();
    const patient = {
      patientId: 'PAT-1001',
      bloodGroup: 'O+',
      allergies: ['Synthetic allergy'],
      activeMedications: [{ name: 'Synthetic medication', dose: '10 mg', frequency: 'daily' }],
      criticalConditions: ['Synthetic condition'],
    };
    const card = createSafetyCard(patient, keys.privateKey, keys.publicKey);
    const encoded = encodeQrPayload(card);
    expect(verifySafetyCard(decodeQrPayload(encoded), keys.publicKey).status).toBe('VALID');
    const tampered = decodeQrPayload(encoded);
    tampered.patient.allergies = [];
    expect(verifySafetyCard(tampered, keys.publicKey).status).toBe('TAMPERED');
    expect(() => decodeQrPayload(`TP1.${'A'.repeat(64 * 1024)}`)).toThrow('oversized');
  });
});
