# TRUST-PASS & DOWNTIME-PASS: Healthcare Cybersecurity Trust Layer

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Crypto](https://img.shields.io/badge/Crypto-Ed25519%20%7C%20SHA--256-green.svg)](security/crypto)
[![Verification](https://img.shields.io/badge/Verification-100%25%20Offline%20Capable-brightgreen.svg)](security/downtime)

A zero-trust cryptographic verification, provenance tracking, risk assessment, and offline disaster-recovery layer for healthcare clinical data pipelines.

---

## 1. Purpose

Clinical data moves across complex environments: Electronic Health Records (EHRs), hospitals, outpatient clinics, laboratories, pharmacies, third-party APIs, and external microservices. When intermediaries are compromised, medical records (such as drug dosages, critical laboratory markers, or documented allergies) can be maliciously altered or inadvertently corrupted in transit.

**TRUST-PASS** establishes an end-to-end cryptographic trust layer that detects unauthorized modification of clinical payloads, validates issuing source systems, assesses technical cyber-risk, and generates actionable clinical explanations.

**DOWNTIME-PASS** provides hospital business continuity during major cyberattacks (e.g. ransomware) or complete EHR outages. By cryptographically signing critical patient safety profiles (allergies, active medications, blood group) prior to outages into a compact QR payload, frontline clinicians can locally verify patient safety cards offline using any modern browser or device without access to the hospital backend, databases, or internet.

---

## 2. Architecture

```text
===================================================================================
TRUST-PASS (Clinical Data Verification Pipeline)
===================================================================================

Clinical Data (EHR)
       │
       ▼
Deterministic Canonicalization (RFC 8785)
       │
       ▼
SHA-256 Payload Digest
       │
       ▼
Ed25519 Digital Signing (Asymmetric Non-Repudiation)
       │
       ▼
Cryptographic Provenance Envelope (Source, Version, Timestamps, Audit Transformations)
       │
       ▼
Deterministic Verification Engine
  ├── Recalculate SHA-256 Digest (Checks for Payload Tampering)
  ├── Verify Ed25519 Signature (Checks Origin & Metadata Tampering)
  └── Source & Freshness Validation
       │
       ▼
Deterministic Risk Engine (Scores 0–100: LOW, MEDIUM, HIGH, CRITICAL)


===================================================================================
DOWNTIME-PASS (Ransomware / Outage Disaster Recovery)
===================================================================================

Synthetic Patient Safety Data (Allergies, Medications, Blood Group)
       │
       ▼
Canonical Representation
       │
       ▼
Ed25519 Digital Signature (Signed by Hospital Authority)
       │
       ▼
Signed Patient Safety Card
       │
       ▼
URL-Safe Base64 QR Encoding (Prefix: 'TP1.')
       │
       ▼
Frontline Device / Offline PWA (Disaster Mode: Network Down, Backend Down)
       │
       ▼
Local Public-Key Cryptographic Verification (No Network, No Backend, No DB)
       ├── [Match]    ──► Status: VALID (Safe for Clinical Emergency Care)
       └── [Tampered] ──► Status: TAMPERED (Alert: Forged / Altered Card)
```

---

## 3. Cryptographic Approach

* **Deterministic Canonicalization (`security/crypto/canonicalize.js`)**:
  Standard `JSON.stringify` does not guarantee deterministic key order. TRUST-PASS recursively sorts object keys lexicographically according to UTF-16 code units (consistent with RFC 8785 JSON Canonicalization Scheme principles) while preserving array order, formatting dates consistently, and omitting undefined values.
* **SHA-256 Integrity Digests (`security/crypto/hash.js`)**:
  Produces reproducible 256-bit hashes of canonical clinical payloads. Comparisons utilize timing-safe equality (`crypto.timingSafeEqual`) to mitigate timing side-channel attacks.
* **Ed25519 Asymmetric Digital Signatures (`security/crypto/sign.js`)**:
  Employs Ed25519 (Edwards-curve Digital Signature Algorithm), offering high verification throughput, small 64-byte signatures, resistance to side-channel attacks, and collision resistance.
* **Public Key Fingerprinting (`security/crypto/keys.js`)**:
  Generates deterministic `keyId` identifiers (`key-<hex16>`) from public key SPKI material to track issuing credentials.

---

## 4. TRUST-PASS Flow

1. **Issuance**: Clinician or EHR enters clinical data (e.g. `Patient P-104, Amoxicillin 500 mg, 3/day`). The issuing system calls `createProvenanceRecord(payload, sourceInfo, privateKey)`.
2. **Transmission**: The signed envelope travels across clinics, labs, and intermediaries. Transformations can be appended via `appendTransformation()`.
3. **Verification**: The consumer calls `verifyIntegrity(record, trustedPublicKey)`.
4. **Risk Scoring**: Findings are passed to `calculateRiskScore(report)`. If authentic: score `0` (`LOW`). If tampered: score `95` (`CRITICAL`).

---

## 5. DOWNTIME-PASS Flow

1. **Pre-Outage Issuance**: During routine care or prior to planned/emergency outages, `createSafetyCard(patientData, privateKey)` creates a signed patient safety card.
2. **QR Encoding**: `encodeQRPayload(signedCard)` produces a compact `TP1.<base64url>` payload suitable for standard QR code display or printed emergency cards.
3. **Ransomware / Outage Scenario**: Hospital network is offline, EHR database is unreachable.
4. **Frontline Verification**: Emergency staff scan the QR code using a tablet or offline browser application.
5. **Immediate Verification**: `verifySafetyCardLocally(qrString, trustedPublicKey)` verifies the signature locally in milliseconds without making any network calls.

---

## 6. Offline Verification Explanation

> **Critical Security Concept: The QR code is NOT the security. The digital signature is the security.**

During a ransomware incident, hospital IT infrastructure may be completely disabled.
`verifySafetyCardLocally()` operates with **zero external dependencies**:
* **No Express / Backend server required**
* **No MongoDB / SQL database required**
* **No Internet / Wi-Fi connection required**

All verification logic relies solely on public-key asymmetric math against the pre-distributed hospital public verification key. If an adversary modifies an allergy from `"Penicillin"` to `"None"`, the mathematical signature check fails deterministically, and the card is rejected as **`TAMPERED`**.

---

## 7. Threat Model

| Threat Actor / Vector | Description | TRUST-PASS Defense |
| :--- | :--- | :--- |
| **Malicious Intermediary (Man-in-the-Middle)** | Alters medication dosage or lab results in transit between systems. | Detected immediately by SHA-256 recalculation (`INTEGRITY_FAILURE`). |
| **Rogue / Spoofed System** | Attacker injects fake clinical record claiming to be from an authorized hospital. | Digital signature check fails (`INVALID_SIGNATURE`) because attacker does not possess the legitimate private key. |
| **Source Spoofing** | Attacker alters the provenance `source.id` to blame another clinic. | Provenance envelope binds the source identity into the signed statement; signature verification fails. |
| **Allergy Tampering in Outage** | Bad actor prints or modifies emergency QR card (e.g. erasing penicillin allergy). | Offline cryptographic signature check fails (`status: 'TAMPERED'`). |
| **Replay / Stale Transmissions** | Attacker resends ancient clinical orders. | Provenance timestamp checks detect stale records and flag `STALE_TIMESTAMP`. |
| **Malformed / Fuzzed Payloads** | Adversary sends garbage bytes or broken JSON to crash verifier. | Resilient error boundaries return structured error reports without throwing unhandled exceptions. |

---

## 8. Security Assumptions

1. **Private Key Confidentiality**: The issuing system's Ed25519 private key is securely stored in a Hardware Security Module (HSM), KMS, or secure vault, and is never leaked.
2. **Trusted Public Key Distribution**: Clinician verification devices possess the genuine public key (or trusted root certificate) of the issuing healthcare system.
3. **System Clock Sanity**: Verifying devices maintain an approximate real-time clock (within acceptable skew) for timestamp freshness checks.

---

## 9. Limitations

* **Detects Modification, Does Not Prevent Origin Error**: If an authorized doctor with valid keys enters incorrect data into the EHR at the moment of entry, cryptography proves authenticity of the author, not medical correctness of the clinical judgment.
* **Non-Confidential Payloads**: Digital signatures and provenance envelopes guarantee authenticity and integrity; they do not encrypt the payload. Patient data confidentiality in transit requires transport-layer encryption (TLS) or field-level encryption if stored at rest.
* **Demonstration Key Management**: Development keys generated via `generateKeyPair()` are for local testing and demonstration. Production deployment requires institutional PKI/HSM key rotation.
* **Risk Score Nature**: Risk scores (`0–100`) are technical cybersecurity risk indicators. They are **not medically validated clinical diagnostic scores**.

---

## 10. Synthetic Data Notice

> [!IMPORTANT]
> **All data used across tests, demonstrations, examples, and documentation is 100% SYNTHETIC AND SIMULATED.**
> No real patient records, protected health information (PHI), or actual clinical records are stored, processed, or committed in this repository.

---

## 11. Setup & Installation

The security module has **zero external runtime dependencies**. It utilizes standard Node.js cryptographic primitives and built-in test frameworks.

### Prerequisites
* Node.js v18+ (tested on Node v24).

### Running Tests
To run all 149 automated security, attack, and judge demo tests:
```bash
./security/run-tests.sh
```
Or via standard npm test inside `security/`:
```bash
cd security
npm test
```

---

## 12. Integration Guide & API Contracts

### For Backend Teammates

```javascript
const security = require('./security');

// 1. Sign and issue clinical data
const ehrKeys = security.generateKeyPair(); // In production, loaded from secure KMS
const record = security.createProvenanceRecord(
  { patientId: 'P-104', medication: 'Amoxicillin', dose: '500 mg', frequency: '3/day' },
  { type: 'EHR', id: 'demo-ehr-01' },
  ehrKeys.privateKey,
  { publicKey: ehrKeys.publicKey }
);

// 2. Verify incoming data
const verification = security.verifyIntegrity(record, ehrKeys.publicKey);

// 3. Compute cybersecurity risk score
const risk = security.calculateRiskScore(verification);
console.log(risk.level); // 'LOW' | 'CRITICAL'
```

### For Frontend Teammates (Browser / PWA / Offline)

```javascript
import { verifySafetyCardLocally } from './security';

// Scanned string from mobile camera / QR scanner
const scannedQrString = 'TP1.eyJjYXJkSWQiOiJDQVJEL...';
const hospitalPublicKey = '-----BEGIN PUBLIC KEY-----\n...';

// 100% offline verification: NO network, NO backend, NO database
const result = verifySafetyCardLocally(scannedQrString, hospitalPublicKey);

if (result.valid) {
  // Status: "VALID"
  console.log('Patient ID:', result.patient.patientId);
  console.log('Blood Group:', result.patient.bloodGroup);
  console.log('Allergies:', result.patient.allergies);
  console.log('Medications:', result.patient.activeMedications);
} else {
  // Status: "TAMPERED"
  alert('SECURITY ALERT: This safety card has been altered or forged!');
  console.error('Tamper Reason:', result.reason);
}
```

---

## 13. Automated Test Coverage (136 Tests across 9 Suites)

1. **`tests/demo.test.js`** (7 tests): Judge presentation scenarios (Genuine card -> VALID, Tampered medication -> INVALID, Fake card -> UNTRUSTED, Expired card -> EXPIRED, EHR offline -> VALID, Allergy erasure -> INVALID).
2. **`tests/ninety-attacks-lab.test.js`** (68 tests): Complete 90-point attack lab evaluating Critical, High, and Medium priority threat vectors with machine-readable ledger export (`attack-lab-report.json`).
3. **`tests/crypto.test.js`** (15 tests): RFC 8785 deterministic canonicalization, SHA-256 avalanche effect, constant-time verification, Ed25519 keypair generation, digital signing, and tamper detection.
4. **`tests/provenance.test.js`** (10 tests): Provenance envelope construction, source validation, audit transformation tracking, and origin spoofing detection.
5. **`tests/risk.test.js`** (9 tests): Deterministic risk scoring, compounding threat calculations, score boundary mapping, and explainability.
6. **`tests/downtime.test.js`** (9 tests): DOWNTIME-PASS safety card generation, allergy tamper detection, medication alteration detection, and expiry checking.
7. **`tests/offline.test.js`** (6 tests): URL-safe Base64 QR encoding, QR decoding, and zero-network client verification.
8. **`tests/attacks.test.js`** (8 tests): Explicit test suite covering Attack Vectors A through G.
9. **`tests/penetration.test.js`** (9 tests): Advanced penetration-style validation (Prototype Pollution, Recursion Depth Bombs, Oversized QR Memory Bombs, Hex Casing, Signature Anti-Malleability, Asymmetric Key Confusion, Null-Byte Injections, Offline Allergy Erasure).

---

## 14. Attack Verification Matrix

| Test Case | Attack Description | Expected Result | Pass Status |
| :--- | :--- | :--- | :--- |
| **Attack A** | Modify clinical lab value (Potassium 4.2 -> 8.2) | `INTEGRITY_FAILURE` (Score >= 85, CRITICAL) | Verified |
| **Attack B** | Modify active medication (Amoxicillin -> Ciprofloxacin) | `INTEGRITY_FAILURE` / `TAMPERED` | Verified |
| **Attack C** | Modify allergy list in safety card (Penicillin -> None) | `TAMPERED` (Offline verifier flags immediately) | Verified |
| **Attack D** | Replace origin source identifier (`demo-ehr-01` -> `rogue-system-99`) | `INVALID_SIGNATURE` (Signature binds source identity) | Verified |
| **Attack E** | Submit corrupted/malformed QR or JSON payloads | Safe failure with structured error, no crash | Verified |
| **Attack F** | Attempt verification using an unauthorized / foreign public key | `INVALID_SIGNATURE` / `TAMPERED` | Verified |
| **Attack G** | Bit-flip or corrupt digital signature bytes | `INVALID_SIGNATURE` | Verified |

---

## 15. License

Published under the [Apache License 2.0](LICENSE).
Third-party dependencies: None (utilizes Node.js standard libraries).
