/**
 * TRUST-PASS Comprehensive Security Attack Test Suite
 *
 * Explicitly tests adversarial attack vectors A through G as defined
 * in the TRUST-PASS security specifications.
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { generateKeyPair, signData, verifyData } = require('../crypto');
const { createProvenanceRecord, verifyIntegrity } = require('../provenance');
const { createSafetyCard, verifySafetyCard, verifySafetyCardLocally, encodeQRPayload } = require('../downtime');
const { calculateRiskScore } = require('../risk');

test('Comprehensive Security Attack Scenarios (Attacks A - G)', async (t) => {
  const hospitalKeys = generateKeyPair();
  const attackerKeys = generateKeyPair();

  const syntheticClinicalData = {
    patientId: 'P-104',
    potassium: 4.2,
    allergies: ['Penicillin'],
    medication: 'Amoxicillin',
    dose: '500 mg',
    frequency: '3/day'
  };

  // ATTACK A: Modify a signed clinical field (Potassium 4.2 -> 8.2)
  await t.test('ATTACK A: Modify a signed clinical field -> detected as INTEGRITY_FAILURE', () => {
    const record = createProvenanceRecord(
      syntheticClinicalData,
      { type: 'EHR', id: 'demo-ehr-01' },
      hospitalKeys.privateKey,
      { publicKey: hospitalKeys.publicKey }
    );

    // Adversary modifies lab value
    const tampered = {
      ...record,
      payload: { ...record.payload, potassium: 8.2 }
    };

    const verification = verifyIntegrity(tampered, hospitalKeys.publicKey);
    assert.strictEqual(verification.valid, false);
    assert.strictEqual(verification.status, 'INTEGRITY_FAILURE');
    assert.strictEqual(verification.integrityValid, false);

    const risk = calculateRiskScore(verification);
    assert.strictEqual(risk.level, 'CRITICAL');
  });

  // ATTACK B: Modify medication (Amoxicillin -> Ciprofloxacin)
  await t.test('ATTACK B: Modify medication in transit -> tamper detected', () => {
    const record = createProvenanceRecord(
      syntheticClinicalData,
      { type: 'EHR', id: 'demo-ehr-01' },
      hospitalKeys.privateKey,
      { publicKey: hospitalKeys.publicKey }
    );

    // Adversary swaps medication
    const tampered = {
      ...record,
      payload: { ...record.payload, medication: 'Ciprofloxacin', dose: '1000 mg' }
    };

    const verification = verifyIntegrity(tampered, hospitalKeys.publicKey);
    assert.strictEqual(verification.valid, false);
    assert.strictEqual(verification.integrityValid, false);
    assert.strictEqual(verification.status, 'INTEGRITY_FAILURE');
  });

  // ATTACK C: Modify allergy (Penicillin -> None) in DOWNTIME-PASS
  await t.test('ATTACK C: Modify allergy in safety card -> tamper detected offline', () => {
    const patientData = {
      patientId: 'P-104',
      bloodGroup: 'O+',
      allergies: ['Penicillin'],
      activeMedications: [{ name: 'Amoxicillin', dose: '500 mg', frequency: '3/day' }],
      criticalConditions: ['Asthma']
    };

    const card = createSafetyCard(patientData, hospitalKeys.privateKey, {
      publicKey: hospitalKeys.publicKey
    });

    // Attacker modifies allergy list to None
    const tamperedCard = {
      ...card,
      patient: { ...card.patient, allergies: ['None'] }
    };

    const verification = verifySafetyCard(tamperedCard, hospitalKeys.publicKey);
    assert.strictEqual(verification.valid, false);
    assert.strictEqual(verification.status, 'TAMPERED');
  });

  // ATTACK D: Replace source identifier (demo-ehr-01 -> rogue-system-99)
  await t.test('ATTACK D: Replace source identifier -> anomaly / signature failure detected', () => {
    const record = createProvenanceRecord(
      syntheticClinicalData,
      { type: 'EHR', id: 'demo-ehr-01' },
      hospitalKeys.privateKey,
      { publicKey: hospitalKeys.publicKey }
    );

    // Adversary alters issuing system ID
    const spoofedRecord = {
      ...record,
      provenance: {
        ...record.provenance,
        source: { type: 'EHR', id: 'rogue-system-99' }
      }
    };

    const verification = verifyIntegrity(spoofedRecord, hospitalKeys.publicKey);
    assert.strictEqual(verification.valid, false);
    assert.strictEqual(verification.signatureValid, false);
    assert.strictEqual(verification.status, 'INVALID_SIGNATURE');
  });

  // ATTACK E: Use malformed signed payload
  await t.test('ATTACK E: Use malformed signed payload -> safe failure, no application crash', () => {
    const malformedInputs = [
      null,
      undefined,
      '',
      '{not-valid-json',
      { payload: null, provenance: {} },
      { payload: {}, provenance: { integrity: {} } },
      'TP1.corrupted-base64-content!@#$'
    ];

    for (const input of malformedInputs) {
      assert.doesNotThrow(() => {
        const vResult = verifyIntegrity(input, hospitalKeys.publicKey);
        assert.strictEqual(vResult.valid, false);
      });

      assert.doesNotThrow(() => {
        const dResult = verifySafetyCardLocally(input, hospitalKeys.publicKey);
        assert.strictEqual(dResult.valid, false);
      });
    }
  });

  // ATTACK F: Try to verify with wrong public key
  await t.test('ATTACK F: Try to verify with wrong public key -> verification fails', () => {
    const record = createProvenanceRecord(
      syntheticClinicalData,
      { type: 'EHR', id: 'demo-ehr-01' },
      hospitalKeys.privateKey,
      { publicKey: hospitalKeys.publicKey }
    );

    // Verifier uses an untrusted / foreign public key
    const verification = verifyIntegrity(record, attackerKeys.publicKey);
    assert.strictEqual(verification.valid, false);
    assert.strictEqual(verification.signatureValid, false);
    assert.strictEqual(verification.status, 'INVALID_SIGNATURE');
  });

  // ATTACK G: Attempt verification with modified signature
  await t.test('ATTACK G: Attempt verification with modified signature -> verification fails', () => {
    const record = createProvenanceRecord(
      syntheticClinicalData,
      { type: 'EHR', id: 'demo-ehr-01' },
      hospitalKeys.privateKey,
      { publicKey: hospitalKeys.publicKey }
    );

    // Bit-flip or corrupt signature characters
    const originalSig = record.provenance.integrity.signature;
    const flippedChar = originalSig[0] === 'A' ? 'B' : 'A';
    const modifiedSig = flippedChar + originalSig.substring(1);

    const tamperedRecord = {
      ...record,
      provenance: {
        ...record.provenance,
        integrity: {
          ...record.provenance.integrity,
          signature: modifiedSig
        }
      }
    };

    const verification = verifyIntegrity(tamperedRecord, hospitalKeys.publicKey);
    assert.strictEqual(verification.valid, false);
    assert.strictEqual(verification.signatureValid, false);
    assert.strictEqual(verification.status, 'INVALID_SIGNATURE');
  });
});
