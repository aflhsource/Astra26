# TRUST-PASS & DOWNTIME-PASS

TRUST-PASS is a clinical-data trust layer prototype. It sits between systems that exchange healthcare data and the applications that consume it, checking whether an exchange is authentic, intact, fresh, authorized, and safe to use.

The project includes a dashboard and an API. The dashboard makes the trust decisions easy to explore; the API performs the verification and keeps the exchange, audit, and Trust Pass records.

## What you can try

The **Demo Lab** in the dashboard runs synthetic exchanges through the backend verification flow. Try a clean exchange, then compare it with cases such as:

- tampered payloads
- replay attacks
- expired exchanges
- unknown sources
- unauthorized transformations
- context mismatches

Depending on the result, an exchange is allowed, sent for review, or quarantined. An allowed exchange can receive a signed **Trust Pass**, which a downstream consumer can verify before using the data.

## How it fits together

```text
React dashboard  →  Express API  →  MongoDB
                         │
                         ├─ source registry
                         ├─ exchange verification
                         ├─ trust scoring and policy
                         ├─ audit trail
                         └─ signed Trust Passes
```

- `client/` — React 19 + TypeScript + Vite dashboard
- `server/` — Express 5 + TypeScript API, backed by MongoDB
- `server/tests/` — API and verification tests
- `security/` — Zero-trust pure cryptographic engine (Ed25519 + SHA-256, zero npm runtime dependencies)

## Requirements

- Node.js 20 or newer
- npm
- MongoDB running locally, or a reachable MongoDB instance

## Run it locally

1. Install dependencies:

   ```bash
   cd server && npm install
   cd ../client && npm install
   ```

2. Configure the API:

   ```bash
   cd server
   cp .env.example .env
   ```

   The defaults expect MongoDB at `mongodb://127.0.0.1:27017/trust_pass` and the dashboard at `http://localhost:5173`.

3. Generate the local demo keys and seed the source registry:

   ```bash
   cd server
   npm run keys:generate
   npm run seed:demo
   ```

4. Start the API in one terminal:

   ```bash
   cd server
   npm run dev
   ```

5. Start the dashboard in another terminal:

   ```bash
   cd client
   npm run dev
   ```

Open the local URL printed by Vite, usually `http://localhost:5173`.

If the API is running somewhere else, set `VITE_API_BASE_URL` before starting the client. It should point to the API base, for example `http://localhost:4000/api/v1`.

## Useful commands

Run these from the relevant directory:

```bash
# client
npm run build
npm run lint

# server
npm run build
npm run lint
npm test
```

The API health endpoint is available at `GET /api/v1/health`.

## A note about the prototype

This is a demonstration and development project, not a production clinical-data system. The bundled keys, seeded records, synthetic payloads, and local defaults are intended for testing the trust flow only. Before using an approach like this in a real environment, add production key management, identity and access controls, operational monitoring, durable audit storage, privacy safeguards, and a thorough compliance review.

## License

See [LICENSE](LICENSE).

---

---

# Security Engineering: TRUST-PASS & DOWNTIME-PASS

[![Crypto](https://img.shields.io/badge/Crypto-Ed25519%20%7C%20SHA--256-green.svg)](security/crypto)
[![Verification](https://img.shields.io/badge/Verification-100%25%20Offline%20Capable-brightgreen.svg)](security/downtime)
[![Tests](https://img.shields.io/badge/Security%20Tests-136%2F136%20PASS-brightgreen.svg)](security/tests)
[![Dependencies](https://img.shields.io/badge/NPM%20Runtime%20Deps-0-blue.svg)](security/package.json)

---

## Security Problem Statement

Healthcare data frequently becomes untrusted when moving across EHRs, labs, clinics, pharmacies, and third-party APIs. A compromised system, malicious intermediary, or insider can silently alter sensitive clinical data in transit — e.g. changing a medication dose from `500mg` to `5000mg` or erasing a documented `Penicillin` allergy.

During ransomware attacks or EHR outages, hospitals fall back to unverified paper processes, risking fatal medical errors with no way to cryptographically verify patient safety data.

---

## Security Architecture

```text
===================================================================================
TRUST-PASS: In-Transit Clinical Data Verification Pipeline
===================================================================================

Clinical Data (EHR)
       │
       ▼
Deterministic Canonicalization (RFC 8785 JSON Canonicalization Scheme)
       │
       ▼
SHA-256 Payload Digest (Constant-time timingSafeEqual comparison)
       │
       ▼
Ed25519 Digital Signing (Asymmetric Non-Repudiation, 64-byte malleability defense)
       │
       ▼
Cryptographic Provenance Envelope (Source, Version, Timestamps, Audit Lineage)
       │
       ▼
Deterministic Verification Engine
  ├── Recalculate SHA-256 Digest     (Detects payload tampering)
  ├── Verify Ed25519 Signature       (Detects source/metadata tampering)
  └── Source & Freshness Validation  (Detects replays, stale records, spoofing)
       │
       ▼
Deterministic Risk Engine (Scores 0–100: LOW → MEDIUM → HIGH → CRITICAL)
       │
       ▼
Policy Decision (ALLOW / REVIEW / QUARANTINE)


===================================================================================
DOWNTIME-PASS: Ransomware / Outage Disaster Recovery
===================================================================================

Synthetic Patient Safety Data (Allergies, Medications, Blood Group)
       │
       ▼
Canonical Representation (RFC 8785 JCS)
       │
       ▼
Ed25519 Digital Signature (Signed by Hospital Authority)
       │
       ▼
Signed Patient Safety Card
       │
       ▼
URL-Safe Base64 QR Encoding (Protocol Prefix: 'TP1.', Max: 64 KB)
       │
       ▼
Frontline Device / Offline Browser/PWA (Disaster Mode: Network Down, EHR Down)
       │
       ▼
Local Cryptographic Verification (No Network, No Backend, No Database)
  ├── [VALID]    ──► Safety card authentic and intact — safe for emergency care
  └── [TAMPERED] ──► Alert: Card forged, modified, or signed by unauthorized entity
```

---

## Security Key Rule

> **"The QR code is NOT the security. The digital signature IS the security."**

QR payloads never define their own trust keys. Verification relies exclusively on pinned hospital public keys. An attacker cannot embed a rogue key into the QR and convince the verifier to trust it.

---

## Security Test Results

### Core Security Engine (`security/`)
**136 / 136 PASS, 0 FAIL** across 9 test suites. Zero external npm runtime dependencies.

```bash
# Run all security tests
cd security
./run-tests.sh

# Run live judge demo scenarios
./run-tests.sh tests/demo.test.js
```

### 90-Point Attack Audit Breakdown

| Category | Count | Description |
| :--- | :--- | :--- |
| **PASS** | 64 | Defended locally by security engine and Express API |
| **NOT_APPLICABLE** | 14 | CI/CD pipeline, physical HSM hardware boundaries |
| **DOCUMENTED_LIMITATION** | 12 | Physical QR card theft, compromised client OS |
| **FAIL** | 0 | Zero vulnerabilities accepted |

---

## Security Threat Matrix

| Attack Scenario | Mechanism | System Response | Result |
| :--- | :--- | :--- | :--- |
| **In-Transit Tampering** | Dose changed (500mg → 5000mg) | SHA-256 digest mismatch → `QUARANTINE` | ✅ PASS |
| **Digital Signature Forgery** | Rogue private key used | Ed25519 fails against hospital key → `INVALID_SIGNATURE` | ✅ PASS |
| **Allergy Tampering (Outage)** | Penicillin erased from QR card | Local digest recomputed → Status: `TAMPERED` | ✅ PASS |
| **Fake QR Generation** | Entirely fake safety card | Rogue key rejected by pinned trust root | ✅ PASS |
| **Public-Key Substitution** | Attacker embeds own key in QR | Verifier ignores QR-embedded keys, uses pinned key only | ✅ PASS |
| **Patient Identity Substitution** | PATIENT-001 → PATIENT-999 | Context mismatch → Policy: `REVIEW` | ✅ PASS |
| **Replay Attack** | Stale transaction resent | Nonce + timestamp → `QUARANTINE` | ✅ PASS |
| **Stale Safety Card** | Card past `expiresAt` | Expiry validation → Status: `EXPIRED` | ✅ PASS |
| **Signature Stripping** | Remove `signature` field | Fail-closed envelope guard catches immediately | ✅ PASS |
| **DoS Buffer Bomb** | QR payload >64 KB | Buffer cap rejects safely before JSON parse | ✅ PASS |
| **Algorithm Confusion** | Claim `RSA-MD5` instead of `Ed25519` | Algorithm whitelist rejects unsupported algorithm | ✅ PASS |
| **Prototype Pollution** | `__proto__` injection via JSON key | `Object.create(null)` + key filter blocks it | ✅ PASS |
| **EHR Ransomware Outage** | Zero network, zero DB, zero server | `verifySafetyCardLocally()` verifies offline → `VALID` | ✅ PASS |

---

## Judge Demo Presentation Scenarios

Run `./security/run-tests.sh tests/demo.test.js` to display:

```text
┌────────────────────────────────────────────────────────────┐
│  SCENARIO 1: Genuine card                                  │  ✅ VALID
└────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────┐
│  SCENARIO 2: Tampered medication (500mg → 5000mg)          │  ❌ TAMPERED
└────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────┐
│  SCENARIO 3: Fake card (attacker-signed rogue key)         │  ❌ UNTRUSTED
└────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────┐
│  SCENARIO 4: Old card (expired Jan 2022)                   │  ❌ EXPIRED
└────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────┐
│  SCENARIO 5: Ransomware Outage — genuine card              │  ✅ VALID (Offline)
└────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────┐
│  SCENARIO 6: Tampered allergy (Penicillin erased)          │  ❌ TAMPERED
└────────────────────────────────────────────────────────────┘
```

---

## Security Module Structure

```text
security/
├── README.md                           (Security API specification)
├── package.json                        (Zero NPM runtime dependencies)
├── index.js                            (Facade: Crypto, Provenance, Risk, Downtime)
├── run-tests.sh                        (136-test automated runner)
│
├── crypto/                             (Phase 1: Cryptographic Primitives)
│   ├── canonicalize.js                 (RFC 8785 JCS + Depth Bomb Defense)
│   ├── hash.js                         (SHA-256 + timingSafeEqual)
│   ├── keys.js                         (Ed25519 KeyPair + SPKI KeyID Fingerprinting)
│   └── sign.js                         (Ed25519 Sign + 64-byte Malleability Defense)
│
├── provenance/                         (Phase 2: Audit Chaining)
│   ├── record.js                       (Signed Provenance Envelopes)
│   └── verify.js                       (Integrity + Signature Verifier + Algorithm Whitelist)
│
├── risk/                               (Phase 3: Cyber-Risk Engine)
│   ├── rules.js                        (Threat Rule Catalog)
│   └── engine.js                       (0–100 Compounding Risk Calculator)
│
├── downtime/                           (Phases 4–5: DOWNTIME-PASS)
│   ├── card.js                         (Signed Patient Safety Cards)
│   ├── qr.js                           (TP1. URL-Safe Base64 Encoding + 64 KB Cap)
│   └── offline-verifier.js             (Zero-Network Client-Side Verifier)
│
└── tests/                              (9 Suites — 136 Tests PASS)
    ├── demo.test.js                    (6 Judge Presentation Scenarios)
    ├── ninety-attacks-lab.test.js      (90-Point Attack Lab + JSON Report)
    ├── crypto.test.js
    ├── provenance.test.js
    ├── risk.test.js
    ├── downtime.test.js
    ├── offline.test.js
    ├── attacks.test.js
    └── penetration.test.js
```

---

## Security Integration Snippets

### Backend Integration (Express / Node.js)
```javascript
const security = require('./security');

// Sign a clinical record
const record = security.createProvenanceRecord(
  { patientId: 'P-104', medication: 'Amoxicillin', dose: '500mg' },
  { type: 'EHR', id: 'demo-ehr-01' },
  privateKey,
  { publicKey }
);

// Verify integrity and score risk
const verification = security.verifyIntegrity(record, publicKey);
const risk = security.calculateRiskScore(verification);
console.log(risk.level); // 'LOW' | 'HIGH' | 'CRITICAL'
```

### Frontend Offline Integration (React / PWA)
```javascript
import { verifySafetyCardLocally } from './security';

// 100% offline: NO network, NO backend, NO database
const result = verifySafetyCardLocally(scannedQrString, hospitalPublicKey);

if (result.valid) {
  console.log('Patient:', result.patient.patientId);
  console.log('Allergies:', result.patient.allergies);
} else {
  alert(`SECURITY ALERT: ${result.status} — ${result.reason}`);
}
```

---

*All patient data (P-104, Amoxicillin 500mg, Penicillin allergy, O+ blood group) is 100% synthetic and simulated for demonstration purposes.*
