/**
 * TRUST-PASS Automated Tests: Cryptographic Foundation (Phase 1)
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  canonicalize,
  hashData,
  verifyHash,
  generateKeyPair,
  computeKeyId,
  signData,
  verifyData
} = require('../crypto');

test('Phase 1: Deterministic Canonicalization', async (t) => {
  await t.test('produces identical output regardless of property order', () => {
    const objA = {
      patientId: 'P-104',
      medication: 'Amoxicillin',
      dose: '500 mg',
      frequency: '3/day'
    };

    const objB = {
      frequency: '3/day',
      dose: '500 mg',
      medication: 'Amoxicillin',
      patientId: 'P-104'
    };

    const canonicalA = canonicalize(objA);
    const canonicalB = canonicalize(objB);

    assert.strictEqual(canonicalA, canonicalB);
    assert.strictEqual(
      canonicalA,
      '{"dose":"500 mg","frequency":"3/day","medication":"Amoxicillin","patientId":"P-104"}'
    );
  });

  await t.test('handles nested objects and arrays deterministically', () => {
    const nestedA = {
      z: 1,
      items: [
        { beta: 'b', alpha: 'a' },
        { delta: 'd', gamma: 'c' }
      ],
      a: { innerB: 2, innerA: 1 }
    };

    const nestedB = {
      a: { innerA: 1, innerB: 2 },
      z: 1,
      items: [
        { alpha: 'a', beta: 'b' },
        { gamma: 'c', delta: 'd' }
      ]
    };

    assert.strictEqual(canonicalize(nestedA), canonicalize(nestedB));
  });

  await t.test('safely handles dates, nulls, and undefined', () => {
    const date = new Date('2026-10-05T12:00:00.000Z');
    const dataWithUndefined = {
      id: 1,
      extra: undefined,
      nullVal: null,
      timestamp: date
    };

    const result = canonicalize(dataWithUndefined);
    assert.strictEqual(
      result,
      '{"id":1,"nullVal":null,"timestamp":"2026-10-05T12:00:00.000Z"}'
    );
  });
});

test('Phase 1: SHA-256 Hashing', async (t) => {
  await t.test('produces identical hash for reordered properties', () => {
    const data1 = { a: 1, b: 2 };
    const data2 = { b: 2, a: 1 };

    const hash1 = hashData(data1);
    const hash2 = hashData(data2);

    assert.strictEqual(hash1, hash2);
    assert.strictEqual(hash1.length, 64);
  });

  await t.test('detects payload alteration via verifyHash', () => {
    const clinicalRecord = {
      patientId: 'P-104',
      potassium: 4.2
    };

    const originalHash = hashData(clinicalRecord);
    const validCheck = verifyHash(clinicalRecord, originalHash);
    assert.strictEqual(validCheck.valid, true);

    const tamperedRecord = {
      patientId: 'P-104',
      potassium: 8.2 // Dangerous modification!
    };

    const tamperedCheck = verifyHash(tamperedRecord, originalHash);
    assert.strictEqual(tamperedCheck.valid, false);
    assert.strictEqual(tamperedCheck.reason, 'Digest mismatch (payload modified)');
  });
});

test('Phase 1: Ed25519 Digital Signing and Verification', async (t) => {
  const keyPair = generateKeyPair();

  await t.test('generates valid Ed25519 key pair with fingerprint', () => {
    assert.ok(keyPair.publicKey.includes('BEGIN PUBLIC KEY'));
    assert.ok(keyPair.privateKey.includes('BEGIN PRIVATE KEY'));
    assert.ok(keyPair.keyId.startsWith('key-'));
    assert.strictEqual(keyPair.algorithm, 'Ed25519');

    const calculatedKeyId = computeKeyId(keyPair.publicKey);
    assert.strictEqual(keyPair.keyId, calculatedKeyId);
  });

  const clinicalData = {
    patientId: 'P-104',
    medication: 'Amoxicillin',
    dose: '500 mg',
    frequency: '3/day'
  };

  await t.test('signs and successfully verifies authentic clinical data', () => {
    const signed = signData(clinicalData, keyPair.privateKey, { keyId: keyPair.keyId });

    assert.ok(signed.signature);
    assert.strictEqual(signed.algorithm, 'Ed25519');
    assert.strictEqual(signed.keyId, keyPair.keyId);

    const verification = verifyData(clinicalData, signed.signature, keyPair.publicKey);
    assert.strictEqual(verification.valid, true);
    assert.strictEqual(verification.reason, 'Signature verified');
  });

  await t.test('verifies data regardless of property ordering at verification time', () => {
    const signed = signData(clinicalData, keyPair.privateKey);

    const reorderedData = {
      frequency: '3/day',
      patientId: 'P-104',
      dose: '500 mg',
      medication: 'Amoxicillin'
    };

    const verification = verifyData(reorderedData, signed.signature, keyPair.publicKey);
    assert.strictEqual(verification.valid, true);
  });

  await t.test('fails verification when clinical payload is tampered', () => {
    const signed = signData(clinicalData, keyPair.privateKey);

    // Tamper medication dose
    const tamperedData = {
      ...clinicalData,
      dose: '1000 mg'
    };

    const verification = verifyData(tamperedData, signed.signature, keyPair.publicKey);
    assert.strictEqual(verification.valid, false);
    assert.match(verification.reason, /Signature verification failed/);
  });

  await t.test('fails verification when verified with the wrong public key', () => {
    const anotherKeyPair = generateKeyPair();
    const signed = signData(clinicalData, keyPair.privateKey);

    const verification = verifyData(clinicalData, signed.signature, anotherKeyPair.publicKey);
    assert.strictEqual(verification.valid, false);
  });

  await t.test('fails verification when signature is modified', () => {
    const signed = signData(clinicalData, keyPair.privateKey);

    // Tamper the signature bytes
    const tamperedSig = signed.signature.slice(0, -4) + 'AAAA';

    const verification = verifyData(clinicalData, tamperedSig, keyPair.publicKey);
    assert.strictEqual(verification.valid, false);
  });

  await t.test('safely handles malformed inputs without throwing', () => {
    const res1 = verifyData(null, 'sig', keyPair.publicKey);
    assert.strictEqual(res1.valid, false);

    const res2 = verifyData(clinicalData, '', keyPair.publicKey);
    assert.strictEqual(res2.valid, false);

    const res3 = verifyData(clinicalData, 'invalid-signature-bytes!@#$', 'not-a-valid-key');
    assert.strictEqual(res3.valid, false);
    assert.ok(res3.reason.includes('failed'));
  });
});
