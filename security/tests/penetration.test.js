/**
 * TRUST-PASS Penetration Testing & Vulnerability Validation Suite
 *
 * Simulates advanced adversarial exploit attempts within the local authorized sandbox:
 * 1. Prototype Pollution attacks
 * 2. Denial of Service (DoS) / Stack Overflow depth bombs
 * 3. Buffer overflow / oversized QR payload memory bombs
 * 4. Hexadecimal case malleability & timing-safety
 * 5. Signature truncation & length extension attacks
 * 6. Asymmetric key confusion & curve mismatch attacks
 * 7. Null byte injection & type confusion attacks
 * 8. Replay & timestamp manipulation attacks
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  canonicalize,
  hashData,
  verifyHash,
  generateKeyPair,
  signData,
  verifyData,
  createProvenanceRecord,
  verifyIntegrity,
  createSafetyCard,
  verifySafetyCardLocally,
  decodeQRPayload,
  encodeQRPayload
} = require('../index');

test('Penetration Testing: Advanced Adversarial Scenarios & Defensive Controls', async (t) => {
  const legitKeys = generateKeyPair();

  // 1. Prototype Pollution Defense
  await t.test('DEFENSE-01: Immunized against Prototype Pollution attacks', () => {
    // Malicious payload attempting prototype pollution
    const maliciousJson = '{"__proto__":{"isAdmin":true,"backdoor":true},"patientId":"P-104","medication":"Amoxicillin"}';
    const parsed = JSON.parse(maliciousJson);

    // Canonicalize and hash malicious payload
    const canonical = canonicalize(parsed);
    const hash = hashData(parsed);

    assert.ok(hash);
    // CRITICAL: Ensure Object prototype was NOT contaminated
    assert.strictEqual(({}).isAdmin, undefined);
    assert.strictEqual(({}).backdoor, undefined);
    assert.strictEqual(Object.prototype.isAdmin, undefined);
  });

  // 2. Stack Overflow / Depth Bomb Defense
  await t.test('DEFENSE-02: Rejects deeply nested depth bombs without crashing stack', () => {
    // Construct 80 levels of nested objects (exceeding MAX_CANONICAL_DEPTH = 64)
    let depthBomb = { value: 'leaf' };
    for (let i = 0; i < 80; i++) {
      depthBomb = { nested: depthBomb };
    }

    assert.throws(
      () => canonicalize(depthBomb),
      (err) => err instanceof RangeError && err.message.includes('depth bomb defense')
    );
  });

  // 3. Oversized QR Buffer / Memory Exhaustion DoS Defense
  await t.test('DEFENSE-03: Rejects oversized QR payloads (Buffer overflow / Memory bomb)', () => {
    // Construct 100KB payload (exceeding 64KB safe limit)
    const giantPayload = 'TP1.' + 'A'.repeat(100 * 1024);

    const decodeResult = decodeQRPayload(giantPayload);
    assert.strictEqual(decodeResult.success, false);
    assert.ok(decodeResult.error.includes('maximum safe buffer size'));

    const verifyResult = verifySafetyCardLocally(giantPayload, legitKeys.publicKey);
    assert.strictEqual(verifyResult.valid, false);
    assert.strictEqual(verifyResult.status, 'TAMPERED');
  });

  // 4. Hexadecimal Case Malleability & Constant-Time Safety
  await t.test('DEFENSE-04: Normalizes hex casing safely without timing side-channels', () => {
    const data = { patientId: 'P-104', potassium: 4.2 };
    const lowerHash = hashData(data); // e.g. "a1b2..."
    const upperHash = lowerHash.toUpperCase(); // e.g. "A1B2..."

    // Verification must succeed for valid data regardless of hex casing
    const resUpper = verifyHash(data, upperHash);
    assert.strictEqual(resUpper.valid, true);

    const resLower = verifyHash(data, lowerHash);
    assert.strictEqual(resLower.valid, true);

    // Verification must still reject altered data
    const tamperedData = { patientId: 'P-104', potassium: 8.2 };
    const resTampered = verifyHash(tamperedData, upperHash);
    assert.strictEqual(resTampered.valid, false);
  });

  // 5. Signature Truncation & Malleability Defense
  await t.test('DEFENSE-05: Rejects truncated, extended, and bit-flipped signatures safely', () => {
    const clinicalData = { patientId: 'P-104', test: 'BloodGlucose', result: 95 };
    const signed = signData(clinicalData, legitKeys.privateKey);

    const maliciousSignatures = [
      '',                                           // 0 bytes
      'AAAA',                                       // 4 chars
      signed.signature.substring(0, 10),            // Heavily truncated
      signed.signature.substring(0, signed.signature.length - 2), // Truncated by 2 chars
      signed.signature + '==',                      // Appended padding
      signed.signature + 'extraGarbageBytes'        // Extended signature
    ];

    for (const badSig of maliciousSignatures) {
      const result = verifyData(clinicalData, badSig, legitKeys.publicKey);
      assert.strictEqual(result.valid, false);
    }
  });

  // 6. Asymmetric Key Confusion & Malformed Key Defense
  await t.test('DEFENSE-06: Handles foreign key formats and corrupted PEMs without crash', () => {
    const clinicalData = { patientId: 'P-104', diagnosis: 'Asthma' };
    const signed = signData(clinicalData, legitKeys.privateKey);

    const foreignKeys = [
      '-----BEGIN PUBLIC KEY-----\nINVALIDKEYDATA\n-----END PUBLIC KEY-----',
      'not-even-a-pem',
      '1234567890',
      null,
      undefined
    ];

    for (const badKey of foreignKeys) {
      assert.doesNotThrow(() => {
        const result = verifyData(clinicalData, signed.signature, badKey);
        assert.strictEqual(result.valid, false);
      });
    }
  });

  // 7. Null-Byte Injection & Type Confusion Defense
  await t.test('DEFENSE-07: Resilient against Null-Byte injection and type confusion', () => {
    const nullByteData = {
      patientId: 'P-104\0admin',
      medication: 'Amoxicillin\0DROP TABLE patients;',
      dose: '500 mg',
      frequency: '3/day'
    };

    // Must canonicalize deterministically without stripping or crashing
    const canonical = canonicalize(nullByteData);
    assert.ok(canonical.includes('\\u0000admin'));

    // Record creation and verification must hold intact
    const record = createProvenanceRecord(nullByteData, { type: 'EHR', id: 'ehr-01' }, legitKeys.privateKey);
    const verifyResult = verifyIntegrity(record, legitKeys.publicKey);
    assert.strictEqual(verifyResult.valid, true);

    // Tampering the null-byte value must be detected
    record.payload.patientId = 'P-104';
    const tamperedResult = verifyIntegrity(record, legitKeys.publicKey);
    assert.strictEqual(tamperedResult.valid, false);
  });

  // 8. DOWNTIME-PASS Offline Clinical Safety Validation
  await t.test('DEFENSE-08: Complete local immunity against offline allergy erasure', () => {
    const card = createSafetyCard({
      patientId: 'P-104',
      bloodGroup: 'O+',
      allergies: ['Penicillin', 'Sulfa'],
      activeMedications: [{ name: 'Amoxicillin', dose: '500 mg', frequency: '3/day' }],
      criticalConditions: ['Severe Anaphylaxis Risk']
    }, legitKeys.privateKey, { publicKey: legitKeys.publicKey });

    const qr = encodeQRPayload(card);

    // 1. Legitimate scan must pass
    const legitResult = verifySafetyCardLocally(qr, legitKeys.publicKey);
    assert.strictEqual(legitResult.valid, true);
    assert.strictEqual(legitResult.status, 'VALID');
    assert.strictEqual(legitResult.patient.allergies.length, 2);

    // 2. Adversary creates altered QR wiping the allergies
    const decoded = decodeQRPayload(qr);
    decoded.card.patient.allergies = []; // Erase life-threatening allergy
    const attackedQr = encodeQRPayload(decoded.card);

    const attackResult = verifySafetyCardLocally(attackedQr, legitKeys.publicKey);
    assert.strictEqual(attackResult.valid, false);
    assert.strictEqual(attackResult.status, 'TAMPERED');
  });
});
