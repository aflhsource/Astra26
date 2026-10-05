/**
 * TRUST-PASS Automated Tests: Offline Local Verification (Phases 6 & 7)
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { generateKeyPair } = require('../crypto');
const {
  createSafetyCard,
  encodeQRPayload,
  decodeQRPayload,
  verifySafetyCardLocally
} = require('../downtime');

test('Phases 6 & 7: QR Payload & Offline Verification', async (t) => {
  const hospitalKeys = generateKeyPair();

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

  const signedCard = createSafetyCard(syntheticPatient, hospitalKeys.privateKey, {
    publicKey: hospitalKeys.publicKey
  });

  await t.test('encodes signed card to URL-safe base64 QR payload string', () => {
    const qrString = encodeQRPayload(signedCard);

    assert.ok(qrString.startsWith('TP1.'));
    assert.doesNotMatch(qrString, /[+/=]/); // URL-safe (no standard + / or padding =)
  });

  await t.test('decodes QR payload accurately back to signed card object', () => {
    const qrString = encodeQRPayload(signedCard);
    const decoded = decodeQRPayload(qrString);

    assert.strictEqual(decoded.success, true);
    assert.strictEqual(decoded.card.patient.patientId, 'P-104');
    assert.strictEqual(decoded.card.patient.bloodGroup, 'O+');
    assert.deepStrictEqual(decoded.card.patient.allergies, ['Penicillin']);
  });

  await t.test('verifies QR payload locally without backend, database, or network (Demo 3: Valid Offline)', () => {
    const qrString = encodeQRPayload(signedCard);

    // Call verifySafetyCardLocally directly on the QR string
    const result = verifySafetyCardLocally(qrString, hospitalKeys.publicKey);

    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.status, 'VALID');
    assert.strictEqual(result.offline, true);
    assert.strictEqual(result.patient.patientId, 'P-104');
    assert.deepStrictEqual(result.patient.allergies, ['Penicillin']);
    assert.strictEqual(result.reason, 'Signature verified: Safety card authentic and intact');
  });

  await t.test('detects tampered QR payload locally without backend (Demo 4: Tampered Offline)', () => {
    const qrString = encodeQRPayload(signedCard);
    const decoded = decodeQRPayload(qrString);

    // Attacker modifies decoded patient data and re-encodes without valid private key
    decoded.card.patient.allergies = ['None'];
    const tamperedQrString = encodeQRPayload(decoded.card);

    const result = verifySafetyCardLocally(tamperedQrString, hospitalKeys.publicKey);

    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.status, 'TAMPERED');
    assert.strictEqual(result.offline, true);
  });

  await t.test('safely handles corrupted or malformed QR strings (Attack E)', () => {
    const res1 = verifySafetyCardLocally('TP1.not-valid-base64!!!@@@', hospitalKeys.publicKey);
    assert.strictEqual(res1.valid, false);
    assert.strictEqual(res1.status, 'TAMPERED');

    const res2 = verifySafetyCardLocally('', hospitalKeys.publicKey);
    assert.strictEqual(res2.valid, false);

    const res3 = verifySafetyCardLocally('{"incomplete":"json"', hospitalKeys.publicKey);
    assert.strictEqual(res3.valid, false);
  });
});
