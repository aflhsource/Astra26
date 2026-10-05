import { createPrivateKey, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { sha256 } from '../crypto/hash.js';
import { sign } from '../crypto/signature.js';
import { getSignableExchange, processExchange } from '../exchanges/exchange.service.js';
import type { ExchangeEnvelope, ExchangePayload } from '../exchanges/exchange.types.js';
import type { DemoScenario, DemoScenarioResult } from './simulation.types.js';

const privateKeyPath = resolve(process.cwd(), '.demo-keys/lab-a-private.pem');

export async function runDemoScenario(scenario: DemoScenario): Promise<DemoScenarioResult> {
  const exchange = createScenarioExchange(scenario);
  if (scenario === 'replay') {
    const first = await processExchange(exchange);
    const second = await processExchange(exchange);
    return {
      scenario,
      exchange: second,
      attempts: [first, second],
      evidence: getScenarioEvidence(scenario),
    };
  }
  return {
    scenario,
    exchange: await processExchange(exchange),
    evidence: getScenarioEvidence(scenario),
  };
}

function getScenarioEvidence(scenario: DemoScenario): DemoScenarioResult['evidence'] {
  switch (scenario) {
    case 'clean':
      return {
        expected: 'Morphine · 9 mL · IV · Aspirin 81 mg',
        received: 'Morphine · 9 mL · IV · Aspirin 81 mg',
      };
    case 'valid-transformation':
      return { expected: 'Glucose · 6.66 mmol/L', received: 'Glucose · 6.66 mmol/L' };
    case 'tamper':
      return {
        expected: 'Morphine · 9 mL · IV · Aspirin 81 mg',
        received: 'Morphine · 90 mL · IV · Aspirin 81 mg',
      };
    case 'replay':
      return { expected: 'One accepted transaction', received: 'Same transaction submitted twice' };
    case 'expired':
      return {
        expected: 'Message inside validity window',
        received: 'Message expired before arrival',
      };
    case 'unknown-source':
      return { expected: 'Registered source LAB-A', received: 'UNKNOWN-UNREGISTERED' };
    case 'unauthorized-transformation':
      return { expected: 'NORMALIZE_UNIT', received: 'DELETE_DIAGNOSTIC_VALUE' };
    case 'context-mismatch':
      return { expected: 'PATIENT-001 · ENC-001', received: 'PATIENT-999 · ENC-001' };
  }
}

function createScenarioExchange(scenario: DemoScenario): ExchangeEnvelope {
  const now = Date.now();
  const sequence = now;
  const issuedAt = new Date(now).toISOString();
  const expiresAt = new Date(now + 300_000).toISOString();
  const medicationScenario = scenario === 'clean' || scenario === 'tamper';
  const resourceType = medicationScenario ? 'MedicationRequest' : 'Observation';
  const originPayload: ExchangePayload = {
    resourceType,
    patientRef: 'PATIENT-001',
    encounterRef: 'ENC-001',
    data: medicationScenario
      ? {
          medication: 'Morphine',
          dose: '9 mL',
          route: 'IV',
          adjunctMedication: 'Aspirin',
          adjunctDose: '81 mg',
          status: 'active',
        }
      : { test: 'Glucose', value: 120, unit: 'mg/dL' },
  };
  const transformedPayload: ExchangePayload = {
    ...originPayload,
    data: { test: 'Glucose', value: 6.66, unit: 'mmol/L' },
  };
  const isTransformed =
    scenario === 'valid-transformation' || scenario === 'unauthorized-transformation';
  const payload = isTransformed ? transformedPayload : originPayload;
  const originHash = sha256(originPayload);
  const payloadHash = sha256(payload);
  const effectiveIssuedAt =
    scenario === 'expired' ? new Date(now - 900_000).toISOString() : issuedAt;
  const effectiveExpiresAt =
    scenario === 'expired' ? new Date(now - 600_000).toISOString() : expiresAt;
  const sourceId = scenario === 'unknown-source' ? 'UNKNOWN-UNREGISTERED' : 'LAB-A';
  const contextPatient = scenario === 'context-mismatch' ? 'PATIENT-999' : 'PATIENT-001';
  const transformation = {
    actorId: 'INTEGRATION-A',
    operation:
      scenario === 'unauthorized-transformation' ? 'DELETE_DIAGNOSTIC_VALUE' : 'NORMALIZE_UNIT',
    inputHash: scenario === 'unauthorized-transformation' ? originHash : originHash,
    outputHash: payloadHash,
    timestamp: issuedAt,
  };
  const unsigned: Omit<ExchangeEnvelope, 'signature'> = {
    transactionId: `TX-DEMO-${randomUUID()}`,
    source: { sourceId, keyId: 'lab-a-key-1' },
    resourceType: resourceType as ExchangeEnvelope['resourceType'],
    context: {
      patientRef: contextPatient,
      encounterRef: 'ENC-001',
      purpose: 'clinical-decision-support',
      audience: 'CLINICAL-CONSUMER',
    },
    payload,
    issuedAt: effectiveIssuedAt,
    expiresAt: effectiveExpiresAt,
    sequence,
    nonce: randomUUID(),
    payloadHash: scenario === 'tamper' ? sha256(originPayload) : payloadHash,
    provenance: {
      originSourceId: 'LAB-A',
      originHash,
      transformations: isTransformed ? [transformation] : [],
    },
  };
  const privateKey = createPrivateKey(readFileSync(privateKeyPath));
  const signed = sign(getSignableExchange({ ...unsigned, signature: '' }), privateKey);
  const exchange: ExchangeEnvelope = { ...unsigned, signature: signed };
  if (scenario === 'tamper') {
    exchange.payload = {
      ...exchange.payload,
      data: { ...exchange.payload.data, dose: '90 mL' },
    };
  }
  return exchange;
}
