import { createPrivateKey, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { sha256 } from '../src/modules/crypto/hash.js';
import { sign } from '../src/modules/crypto/signature.js';
import { getSignableExchange } from '../src/modules/exchanges/exchange.service.js';
import type { ExchangeEnvelope } from '../src/modules/exchanges/exchange.types.js';

const sourceDefinitions: Record<string, { keyId: string; privateKeyFile: string }> = {
  'LAB-A': { keyId: 'lab-a-key-1', privateKeyFile: 'lab-a-private.pem' },
  'EHR-A': { keyId: 'ehr-a-key-1', privateKeyFile: 'ehr-a-private.pem' },
  'PHARMACY-A': { keyId: 'pharmacy-a-key-1', privateKeyFile: 'pharmacy-a-private.pem' },
  'UNKNOWN-SOURCE': {
    keyId: 'unknown-source-key-1',
    privateKeyFile: 'unknown-source-private.pem',
  },
};
const sourceId = process.env.DEMO_SOURCE_ID ?? 'LAB-A';
const sourceDefinition = sourceDefinitions[sourceId];
if (!sourceDefinition) {
  throw new Error(`Unsupported DEMO_SOURCE_ID: ${sourceId}`);
}
const sequence = Number.parseInt(process.env.DEMO_SEQUENCE ?? '1', 10);
if (!Number.isSafeInteger(sequence) || sequence <= 0) {
  throw new Error('DEMO_SEQUENCE must be a positive integer');
}
const resolvedPrivateKeyPath = resolve(
  process.cwd(),
  `.demo-keys/${sourceDefinition.privateKeyFile}`,
);
const issuedAt = new Date().toISOString();
const expiresAt = new Date(Date.now() + 300_000).toISOString();

const exchangeWithoutSignature: Omit<ExchangeEnvelope, 'signature'> = {
  transactionId: `TX-DEMO-${randomUUID()}`,
  source: { sourceId, keyId: sourceDefinition.keyId },
  resourceType: 'Observation',
  context: {
    patientRef: 'PATIENT-001',
    encounterRef: 'ENC-001',
    purpose: 'clinical-decision-support',
    audience: 'CLINICAL-AI',
  },
  payload: {
    resourceType: 'Observation',
    patientRef: 'PATIENT-001',
    encounterRef: 'ENC-001',
    data: { test: 'Glucose', value: 120, unit: 'mg/dL' },
  },
  issuedAt,
  expiresAt,
  sequence,
  nonce: randomUUID(),
  payloadHash: sha256({
    resourceType: 'Observation',
    patientRef: 'PATIENT-001',
    encounterRef: 'ENC-001',
    data: { test: 'Glucose', value: 120, unit: 'mg/dL' },
  }),
  provenance: {
    originSourceId: sourceId,
    originHash: sha256({
      resourceType: 'Observation',
      patientRef: 'PATIENT-001',
      encounterRef: 'ENC-001',
      data: { test: 'Glucose', value: 120, unit: 'mg/dL' },
    }),
    transformations: [],
  },
};

const privateKey = createPrivateKey(readFileSync(resolvedPrivateKeyPath));
const exchange: ExchangeEnvelope = {
  ...exchangeWithoutSignature,
  signature: sign(getSignableExchange({ ...exchangeWithoutSignature, signature: '' }), privateKey),
};

process.stdout.write(`${JSON.stringify(exchange, null, 2)}\n`);
