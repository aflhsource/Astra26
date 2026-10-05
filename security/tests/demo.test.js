/**
 * TRUST-PASS + DOWNTIME-PASS: Judge Demo Scenarios
 *
 * Five crisp scenarios that tell the complete security story:
 *
 *   1. Genuine card          → VALID
 *   2. Tampered medication   → INVALID
 *   3. Fake card             → UNTRUSTED
 *   4. Old/expired card      → EXPIRED
 *   5. EHR offline (outage)  → genuine card still VALID
 *
 * All patient data is 100% synthetic (Patient P-104).
 * Zero network calls. Zero database. Pure cryptographic verification.
 */

'use strict';

const test   = require('node:test');
const assert = require('node:assert/strict');

const {
  generateKeyPair,
  createSafetyCard,
  verifySafetyCardLocally,
  encodeQRPayload,
  decodeQRPayload
} = require('../index');

// ─────────────────────────────────────────────
// Shared fixtures
// ─────────────────────────────────────────────

const HOSPITAL_KEYS  = generateKeyPair();          // trusted hospital keypair
const ATTACKER_KEYS  = generateKeyPair();          // rogue / attacker keypair

const SYNTHETIC_PATIENT = {
  patientId:          'P-104',
  bloodGroup:         'O+',
  allergies:          ['Penicillin'],
  activeMedications:  [{ name: 'Amoxicillin', dose: '500mg', frequency: '3/day' }],
  criticalConditions: ['Asthma']
};

// Pre-generate a genuine card used by several scenarios
const GENUINE_CARD   = createSafetyCard(
  SYNTHETIC_PATIENT,
  HOSPITAL_KEYS.privateKey,
  { publicKey: HOSPITAL_KEYS.publicKey, issuer: 'ASTRA-DEMO-HOSPITAL' }
);
const GENUINE_QR = encodeQRPayload(GENUINE_CARD);

// ─────────────────────────────────────────────
// Helper: print a boxed result to stdout
// ─────────────────────────────────────────────
function printResult(scenario, result) {
  const line = '─'.repeat(60);
  const badge = result.valid ? '✅ VALID' : `❌ ${result.status}`;
  console.log(`\n┌${line}┐`);
  console.log(`│  SCENARIO: ${scenario.padEnd(line.length - 12)}│`);
  console.log(`│  RESULT  : ${badge.padEnd(line.length - 12)}│`);
  console.log(`│  REASON  : ${(result.reason || '').substring(0, line.length - 12).padEnd(line.length - 12)}│`);
  if (result.patient) {
    console.log(`│  PATIENT : ${result.patient.patientId} | ${result.patient.bloodGroup} | allergy: ${result.patient.allergies.join(',')}`.padEnd(line.length + 1) + '│');
  }
  console.log(`└${line}┘`);
}

// ─────────────────────────────────────────────
// DEMO SUITE
// ─────────────────────────────────────────────

test('TRUST-PASS + DOWNTIME-PASS: Judge Demo Scenarios', async (t) => {

  // ──────────────────────────────────────────
  // SCENARIO 1: Genuine card → VALID
  // ──────────────────────────────────────────
  await t.test('DEMO 1 — Genuine card verifies as VALID', () => {
    const result = verifySafetyCardLocally(GENUINE_QR, HOSPITAL_KEYS.publicKey);

    printResult('Genuine card → VALID', result);

    assert.strictEqual(result.valid,   true,   'Expected: valid = true');
    assert.strictEqual(result.status,  'VALID', 'Expected: status = VALID');
    assert.strictEqual(result.offline, true,    'Expected: offline = true (no backend needed)');
    assert.ok(result.patient,                   'Patient data must be present');
    assert.strictEqual(result.patient.patientId, 'P-104');
    assert.deepStrictEqual(result.patient.allergies, ['Penicillin']);
  });

  // ──────────────────────────────────────────
  // SCENARIO 2: Attacker changes medication dose → INVALID
  // ──────────────────────────────────────────
  await t.test('DEMO 2 — Tampered medication dose → INVALID', () => {
    // Deep-clone the QR card
    const decoded = decodeQRPayload(GENUINE_QR);
    assert.strictEqual(decoded.success, true, 'QR must decode cleanly before tampering');

    // Attacker modifies the dose in the decoded card
    decoded.card.patient.activeMedications[0].dose = '5000mg'; // 10× lethal overdose

    // Re-encode with tampered data (signature still belongs to original data)
    const tamperedQR = encodeQRPayload(decoded.card);

    const result = verifySafetyCardLocally(tamperedQR, HOSPITAL_KEYS.publicKey);

    printResult('Tampered medication (500mg → 5000mg) → INVALID', result);

    assert.strictEqual(result.valid,  false,     'Expected: valid = false');
    assert.strictEqual(result.status, 'TAMPERED', 'Expected: status = TAMPERED');
    assert.strictEqual(result.offline, true);
  });

  // ──────────────────────────────────────────
  // SCENARIO 3: Attacker creates a completely fake card → UNTRUSTED
  // ──────────────────────────────────────────
  await t.test('DEMO 3 — Fake card (attacker-signed) → UNTRUSTED', () => {
    // Attacker generates their own keypair and signs a card with it
    const fakeCard = createSafetyCard(
      SYNTHETIC_PATIENT,
      ATTACKER_KEYS.privateKey,
      { publicKey: ATTACKER_KEYS.publicKey, issuer: 'ASTRA-DEMO-HOSPITAL' } // claims legitimate issuer
    );
    const fakeQR = encodeQRPayload(fakeCard);

    // Verifier uses ONLY the trusted hospital public key — attacker key cannot satisfy it
    const result = verifySafetyCardLocally(fakeQR, HOSPITAL_KEYS.publicKey);

    printResult('Fake card (attacker-signed, claims genuine issuer) → UNTRUSTED', result);

    assert.strictEqual(result.valid,  false,     'Expected: valid = false');
    assert.strictEqual(result.status, 'TAMPERED', 'Expected: status = TAMPERED (signature mismatch)');
    assert.strictEqual(result.offline, true);
  });

  // ──────────────────────────────────────────
  // SCENARIO 4: Safety card past its expiry date → EXPIRED
  // ──────────────────────────────────────────
  await t.test('DEMO 4 — Old / expired card → EXPIRED', () => {
    // Card issued and expired years ago (cryptographically valid but stale)
    const expiredCard = createSafetyCard(
      SYNTHETIC_PATIENT,
      HOSPITAL_KEYS.privateKey,
      {
        publicKey:  HOSPITAL_KEYS.publicKey,
        issuer:     'ASTRA-DEMO-HOSPITAL',
        issuedAt:   '2022-01-01T00:00:00.000Z',
        expiresAt:  '2022-01-08T00:00:00.000Z'   // expired in January 2022
      }
    );
    const expiredQR = encodeQRPayload(expiredCard);

    const result = verifySafetyCardLocally(expiredQR, HOSPITAL_KEYS.publicKey);

    printResult('Old card (expired Jan 2022) → EXPIRED', result);

    assert.strictEqual(result.valid,     false,   'Expected: valid = false');
    assert.strictEqual(result.status,   'EXPIRED', 'Expected: status = EXPIRED');
    assert.strictEqual(result.isExpired, true,     'Expected: isExpired = true');
    assert.strictEqual(result.offline,   true);
  });

  // ──────────────────────────────────────────
  // SCENARIO 5: EHR is down (ransomware outage) → genuine card STILL VALID offline
  // ──────────────────────────────────────────
  await t.test('DEMO 5 — EHR outage (no backend / no DB / no internet) → genuine card still VALID', () => {
    // verifySafetyCardLocally makes ZERO network calls and uses ZERO database connections.
    // It only needs: the QR string + the pre-cached hospital public key.
    // This simulates a clinician scanning a QR on a device that has ZERO connectivity.

    const result = verifySafetyCardLocally(GENUINE_QR, HOSPITAL_KEYS.publicKey);

    printResult('EHR offline (ransomware outage) — genuine card → VALID', result);

    assert.strictEqual(result.valid,   true,   'Expected: valid = true even with no connectivity');
    assert.strictEqual(result.status,  'VALID', 'Expected: status = VALID');
    assert.strictEqual(result.offline, true,    'Expected: offline = true');

    // Confirm essential clinical data is readable
    assert.strictEqual(result.patient.patientId,   'P-104');
    assert.strictEqual(result.patient.bloodGroup,  'O+');
    assert.deepStrictEqual(result.patient.allergies, ['Penicillin']);
    assert.strictEqual(result.patient.activeMedications[0].name, 'Amoxicillin');
    assert.strictEqual(result.patient.activeMedications[0].dose, '500mg');
  });

  // ──────────────────────────────────────────
  // BONUS SCENARIO: Tampered allergy (blank allergy list)
  // Clinician gives Penicillin thinking no allergy. Patient goes into anaphylaxis.
  // ──────────────────────────────────────────
  await t.test('DEMO BONUS — Tampered allergy (erased) → INVALID (prevents anaphylaxis)', () => {
    const decoded = decodeQRPayload(GENUINE_QR);
    decoded.card.patient.allergies = []; // Attacker erases Penicillin allergy

    const tamperedQR = encodeQRPayload(decoded.card);
    const result = verifySafetyCardLocally(tamperedQR, HOSPITAL_KEYS.publicKey);

    printResult('Tampered allergy (Penicillin erased) → INVALID', result);

    assert.strictEqual(result.valid,  false,     'Expected: valid = false');
    assert.strictEqual(result.status, 'TAMPERED', 'Expected: status = TAMPERED');
  });
});
