import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { connectDatabase, disconnectDatabase } from '../src/database/connection.js';
import { env } from '../src/config/env.js';
import { upsertSource } from '../src/modules/sources/source.repository.js';
import type { CreateSourceInput } from '../src/modules/sources/source.types.js';

const keyDirectory = resolve(process.cwd(), '.demo-keys');

type DemoSource = CreateSourceInput & { publicKeyFile: string };

const demoSources: DemoSource[] = [
  {
    sourceId: 'LAB-A',
    name: 'Laboratory A',
    role: 'SOURCE',
    type: 'LAB',
    status: 'ACTIVE',
    keyId: 'lab-a-key-1',
    publicKey: '',
    publicKeyFile: 'lab-a-public.pem',
    allowedTransformations: [],
  },
  {
    sourceId: 'EHR-A',
    name: 'Hospital EHR A',
    role: 'SOURCE',
    type: 'EHR',
    status: 'ACTIVE',
    keyId: 'ehr-a-key-1',
    publicKey: '',
    publicKeyFile: 'ehr-a-public.pem',
    allowedTransformations: [],
  },
  {
    sourceId: 'PHARMACY-A',
    name: 'Pharmacy A',
    role: 'SOURCE',
    type: 'PHARMACY',
    status: 'ACTIVE',
    keyId: 'pharmacy-a-key-1',
    publicKey: '',
    publicKeyFile: 'pharmacy-a-public.pem',
    allowedTransformations: [],
  },
  {
    sourceId: 'INTEGRATION-A',
    name: 'Clinical Integration Service A',
    role: 'TRANSFORMER',
    type: 'INTEGRATION',
    status: 'ACTIVE',
    keyId: 'integration-a-key-1',
    publicKey: '',
    publicKeyFile: 'integration-a-public.pem',
    allowedTransformations: [
      'MAP_LAB_RESULT_TO_OBSERVATION',
      'NORMALIZE_UNIT',
      'FHIR_INSPIRED_MAPPING',
    ],
  },
  {
    sourceId: 'CLINICAL-CONSUMER',
    name: 'Clinical Consumer System',
    role: 'CONSUMER',
    type: 'CONSUMER',
    status: 'ACTIVE',
    keyId: 'clinical-consumer-key-1',
    publicKey: '',
    publicKeyFile: 'clinical-consumer-public.pem',
    allowedTransformations: [],
  },
  {
    sourceId: 'UNKNOWN-SOURCE',
    name: 'Unknown Source',
    role: 'SOURCE',
    type: 'EHR',
    status: 'REVOKED',
    keyId: 'unknown-source-key-1',
    publicKey: '',
    publicKeyFile: 'unknown-source-public.pem',
    allowedTransformations: [],
  },
];

async function seed(): Promise<void> {
  await connectDatabase(env.MONGODB_URI);
  try {
    for (const source of demoSources) {
      const { publicKeyFile, ...sourceInput } = source;
      const publicKey = readFileSync(resolve(keyDirectory, publicKeyFile), 'utf8');
      await upsertSource({ ...sourceInput, publicKey });
      console.log(`${source.sourceId}: seeded`);
    }
  } finally {
    await disconnectDatabase();
  }
}

seed().catch((error: unknown) => {
  console.error(
    JSON.stringify({ level: 'error', event: 'demo_seed_failed', error: String(error) }),
  );
  process.exitCode = 1;
});
