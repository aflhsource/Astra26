/**
 * TRUST-PASS Automated Tests: DOWNTIME-PASS Safety Card (Phase 5)
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { generateKeyPair } = require('../crypto');
const { createSafetyCard, verifySafetyCard } = require('../downtime');

test('Phase 5: DOWNTIME-PASS Signed Patient Safety Card', async (t) => {
  const hospitalKeys = generateKeyPair();

  // 100% Synthetic Patient Data
  const syntheticPatient = {
    patientId: 'P-104',
    bloodGroup: 'O+',
    allergies: ['Penicillin'],
    activeMedications: [
      {
        name: 'Amoxicillin',
        dose: '500 mg',
        frequency: '3/day'
      }
    ],
    criticalConditions: ['Asthma']
  };

  await t.test('creates standard signed patient safety card (Demo 3)', () => {
    const card = createSafetyCard(syntheticPatient, hospitalKeys.privateKey, {
      publicKey: hospitalKeys.publicKey,
      issuer: 'METRO-REGIONAL-HOSPITAL'
    });

    assert.ok(card.cardId.startsWith('CARD-P-104-'));
    assert.strictEqual(card.issuer, 'METRO-REGIONAL-HOSPITAL');
    assert.strictEqual(card.patient.patientId, 'P-104');
    assert.strictEqual(card.patient.bloodGroup, 'O+');
    assert.deepStrictEqual(card.patient.allergies, ['Penicillin']);
    assert.strictEqual(card.integrity.algorithm, 'SHA-256');
    assert.strictEqual(card.integrity.signatureAlgorithm, 'Ed25519');
    assert.ok(card.integrity.signature);
    assert.strictEqual(card.integrity.keyId, hospitalKeys.keyId);
  });

  await t.test('verifies authentic safety card successfully (Status: VALID)', () => {
    const card = createSafetyCard(syntheticPatient, hospitalKeys.privateKey, {
      publicKey: hospitalKeys.publicKey
    });

    const report = verifySafetyCard(card, hospitalKeys.publicKey);

    assert.strictEqual(report.valid, true);
    assert.strictEqual(report.status, 'VALID');
    assert.strictEqual(report.patient.patientId, 'P-104');
    assert.deepStrictEqual(report.patient.allergies, ['Penicillin']);
  });

  await t.test('detects tampered allergy (Demo 4 & Attack C: Penicillin -> None)', () => {
    const card = createSafetyCard(syntheticPatient, hospitalKeys.privateKey, {
      publicKey: hospitalKeys.publicKey
    });

    // Attacker alters allergy to "None"
    const tamperedCard = {
      ...card,
      patient: {
        ...card.patient,
        allergies: ['None'] // Dangerous clinical alteration!
      }
    };

    const report = verifySafetyCard(tamperedCard, hospitalKeys.publicKey);

    assert.strictEqual(report.valid, false);
    assert.strictEqual(report.status, 'TAMPERED');
    assert.ok(report.reason.includes('Tamper detected'));
  });

  await t.test('detects tampered blood group (O+ -> AB-)', () => {
    const card = createSafetyCard(syntheticPatient, hospitalKeys.privateKey, {
      publicKey: hospitalKeys.publicKey
    });

    const tamperedCard = {
      ...card,
      patient: {
        ...card.patient,
        bloodGroup: 'AB-'
      }
    };

    const report = verifySafetyCard(tamperedCard, hospitalKeys.publicKey);

    assert.strictEqual(report.valid, false);
    assert.strictEqual(report.status, 'TAMPERED');
  });

  await t.test('detects tampered active medications (Attack B)', () => {
    const card = createSafetyCard(syntheticPatient, hospitalKeys.privateKey, {
      publicKey: hospitalKeys.publicKey
    });

    const tamperedCard = {
      ...card,
      patient: {
        ...card.patient,
        activeMedications: [{ name: 'Amoxicillin', dose: '1000 mg', frequency: '5/day' }]
      }
    };

    const report = verifySafetyCard(tamperedCard, hospitalKeys.publicKey);

    assert.strictEqual(report.valid, false);
    assert.strictEqual(report.status, 'TAMPERED');
  });

  await t.test('detects unauthorized issuer or cardId modification', () => {
    const card = createSafetyCard(syntheticPatient, hospitalKeys.privateKey, {
      publicKey: hospitalKeys.publicKey
    });

    const tamperedCard = {
      ...card,
      issuer: 'ROGUE-CLINIC'
    };

    const report = verifySafetyCard(tamperedCard, hospitalKeys.publicKey);

    assert.strictEqual(report.valid, false);
    assert.strictEqual(report.status, 'TAMPERED');
  });

  await t.test('fails verification when verified with the wrong public key (Attack F)', () => {
    const attackerKeys = generateKeyPair();
    const card = createSafetyCard(syntheticPatient, hospitalKeys.privateKey, {
      publicKey: hospitalKeys.publicKey
    });

    const report = verifySafetyCard(card, attackerKeys.publicKey);

    assert.strictEqual(report.valid, false);
    assert.strictEqual(report.status, 'TAMPERED');
  });

  await t.test('flags expired cards appropriately', () => {
    const expiredCard = createSafetyCard(syntheticPatient, hospitalKeys.privateKey, {
      publicKey: hospitalKeys.publicKey,
      issuedAt: '2020-01-01T00:00:00.000Z',
      expiresAt: '2020-01-08T00:00:00.000Z'
    });

    const report = verifySafetyCard(expiredCard, hospitalKeys.publicKey);

    assert.strictEqual(report.valid, false);
    assert.strictEqual(report.status, 'EXPIRED');
    assert.strictEqual(report.isExpired, true);
  });
});
