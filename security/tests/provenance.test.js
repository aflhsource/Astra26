/**
 * TRUST-PASS Automated Tests: Provenance + Integrity (Phase 2)
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { generateKeyPair } = require('../crypto');
const {
  createProvenanceRecord,
  appendTransformation,
  verifyIntegrity
} = require('../provenance');

test('Phase 2: Provenance Creation & Integrity Verification', async (t) => {
  const ehrKeys = generateKeyPair();

  const clinicalData = {
    patientId: 'P-104',
    medication: 'Amoxicillin',
    dose: '500 mg',
    frequency: '3/day'
  };

  await t.test('creates standard provenance envelope with SHA-256 and Ed25519 signature', () => {
    const record = createProvenanceRecord(
      clinicalData,
      { type: 'EHR', id: 'demo-ehr-01' },
      ehrKeys.privateKey,
      { publicKey: ehrKeys.publicKey }
    );

    assert.deepStrictEqual(record.payload, clinicalData);
    assert.strictEqual(record.provenance.source.type, 'EHR');
    assert.strictEqual(record.provenance.source.id, 'demo-ehr-01');
    assert.strictEqual(record.provenance.version, 1);
    assert.strictEqual(record.provenance.integrity.algorithm, 'SHA-256');
    assert.strictEqual(record.provenance.integrity.signatureAlgorithm, 'Ed25519');
    assert.ok(record.provenance.integrity.hash);
    assert.ok(record.provenance.integrity.signature);
    assert.strictEqual(record.provenance.integrity.keyId, ehrKeys.keyId);
  });

  await t.test('verifies genuine unmodified clinical record (Status: VALID)', () => {
    const record = createProvenanceRecord(
      clinicalData,
      { type: 'EHR', id: 'demo-ehr-01' },
      ehrKeys.privateKey,
      { publicKey: ehrKeys.publicKey }
    );

    const report = verifyIntegrity(record, ehrKeys.publicKey);

    assert.strictEqual(report.valid, true);
    assert.strictEqual(report.status, 'VALID');
    assert.strictEqual(report.integrityValid, true);
    assert.strictEqual(report.signatureValid, true);
    assert.strictEqual(report.sourceKnown, true);
    assert.strictEqual(report.findings.length, 0);
  });

  await t.test('detects unauthorized clinical payload modification (Demo 2: Potassium 4.2 -> 8.2)', () => {
    const labData = {
      patientId: 'P-104',
      potassium: 4.2,
      unit: 'mEq/L'
    };

    const record = createProvenanceRecord(
      labData,
      { type: 'LAB', id: 'central-lab-01' },
      ehrKeys.privateKey,
      { publicKey: ehrKeys.publicKey }
    );

    // Attacker modifies clinical payload in transit
    const tamperedRecord = {
      ...record,
      payload: {
        ...record.payload,
        potassium: 8.2 // Critical alteration!
      }
    };

    const report = verifyIntegrity(tamperedRecord, ehrKeys.publicKey);

    assert.strictEqual(report.valid, false);
    assert.strictEqual(report.status, 'INTEGRITY_FAILURE');
    assert.strictEqual(report.integrityValid, false);
    assert.ok(report.findings.some(f => f.includes('does not match claimed digest')));
  });

  await t.test('detects unauthorized medication tampering (Attack B: Amoxicillin -> Ciprofloxacin)', () => {
    const record = createProvenanceRecord(
      clinicalData,
      { type: 'EHR', id: 'demo-ehr-01' },
      ehrKeys.privateKey,
      { publicKey: ehrKeys.publicKey }
    );

    const tamperedRecord = {
      ...record,
      payload: {
        ...record.payload,
        medication: 'Ciprofloxacin',
        dose: '750 mg'
      }
    };

    const report = verifyIntegrity(tamperedRecord, ehrKeys.publicKey);

    assert.strictEqual(report.valid, false);
    assert.strictEqual(report.integrityValid, false);
    assert.strictEqual(report.status, 'INTEGRITY_FAILURE');
  });

  await t.test('detects origin spoofing / source replacement (Attack D: demo-ehr-01 -> rogue-system-99)', () => {
    const record = createProvenanceRecord(
      clinicalData,
      { type: 'EHR', id: 'demo-ehr-01' },
      ehrKeys.privateKey,
      { publicKey: ehrKeys.publicKey }
    );

    // Attacker modifies the source to pretend it was issued by another system
    const tamperedRecord = {
      ...record,
      provenance: {
        ...record.provenance,
        source: {
          type: 'EHR',
          id: 'rogue-system-99'
        }
      }
    };

    const report = verifyIntegrity(tamperedRecord, ehrKeys.publicKey);

    assert.strictEqual(report.valid, false);
    // Because the digital signature binds the source ID, signature verification fails!
    assert.strictEqual(report.signatureValid, false);
    assert.strictEqual(report.status, 'INVALID_SIGNATURE');
  });

  await t.test('fails verification when verified with the wrong public key (Attack F)', () => {
    const untrustedKeys = generateKeyPair();
    const record = createProvenanceRecord(
      clinicalData,
      { type: 'EHR', id: 'demo-ehr-01' },
      ehrKeys.privateKey,
      { publicKey: ehrKeys.publicKey }
    );

    const report = verifyIntegrity(record, untrustedKeys.publicKey);

    assert.strictEqual(report.valid, false);
    assert.strictEqual(report.signatureValid, false);
    assert.strictEqual(report.status, 'INVALID_SIGNATURE');
  });

  await t.test('fails verification when signature is corrupted (Attack G)', () => {
    const record = createProvenanceRecord(
      clinicalData,
      { type: 'EHR', id: 'demo-ehr-01' },
      ehrKeys.privateKey,
      { publicKey: ehrKeys.publicKey }
    );

    const tamperedRecord = {
      ...record,
      provenance: {
        ...record.provenance,
        integrity: {
          ...record.provenance.integrity,
          signature: record.provenance.integrity.signature.slice(0, -4) + 'ZZZZ'
        }
      }
    };

    const report = verifyIntegrity(tamperedRecord, ehrKeys.publicKey);

    assert.strictEqual(report.valid, false);
    assert.strictEqual(report.signatureValid, false);
  });

  await t.test('tracks audit transformations and preserves verifiable lineage', () => {
    const labKeys = generateKeyPair();
    const originalRecord = createProvenanceRecord(
      { test: 'Glucose', value: 100, unit: 'mg/dL' },
      { type: 'LAB', id: 'lab-01' },
      ehrKeys.privateKey
    );

    const transformed = appendTransformation(
      originalRecord,
      {
        system: 'CONVERTER',
        action: 'UNIT_STANDARDIZATION',
        details: { from: 'mg/dL', to: 'mmol/L' }
      },
      { test: 'Glucose', value: 5.55, unit: 'mmol/L' },
      labKeys.privateKey
    );

    assert.strictEqual(transformed.provenance.version, 2);
    assert.strictEqual(transformed.provenance.transformations.length, 1);
    assert.strictEqual(transformed.provenance.transformations[0].action, 'UNIT_STANDARDIZATION');
    assert.strictEqual(transformed.provenance.previousHash, originalRecord.provenance.integrity.hash);

    const report = verifyIntegrity(transformed, labKeys.publicKey);
    assert.strictEqual(report.valid, true);
    assert.strictEqual(report.integrityValid, true);
    assert.strictEqual(report.signatureValid, true);
  });

  await t.test('safely handles missing or malformed records without crashing (Attack E)', () => {
    const res1 = verifyIntegrity(null, ehrKeys.publicKey);
    assert.strictEqual(res1.valid, false);

    const res2 = verifyIntegrity({}, ehrKeys.publicKey);
    assert.strictEqual(res2.valid, false);

    const res3 = verifyIntegrity({ payload: 'not-an-object', provenance: {} }, ehrKeys.publicKey);
    assert.strictEqual(res3.valid, false);
  });
});
