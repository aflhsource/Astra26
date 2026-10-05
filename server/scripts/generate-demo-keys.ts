import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { generateEd25519KeyPair } from '../src/modules/crypto/signature.js';

interface DemoKeyDefinition {
  name: string;
  privateFile: string;
  publicFile: string;
}

const demoKeys: DemoKeyDefinition[] = [
  { name: 'LAB-A', privateFile: 'lab-a-private.pem', publicFile: 'lab-a-public.pem' },
  { name: 'EHR-A', privateFile: 'ehr-a-private.pem', publicFile: 'ehr-a-public.pem' },
  {
    name: 'PHARMACY-A',
    privateFile: 'pharmacy-a-private.pem',
    publicFile: 'pharmacy-a-public.pem',
  },
  {
    name: 'UNKNOWN-SOURCE',
    privateFile: 'unknown-source-private.pem',
    publicFile: 'unknown-source-public.pem',
  },
  {
    name: 'TRUST-PASS-GATEWAY',
    privateFile: 'gateway-private.pem',
    publicFile: 'gateway-public.pem',
  },
];

export function generateDemoKeys(outputDirectory = resolve(process.cwd(), '.demo-keys')): void {
  mkdirSync(outputDirectory, { recursive: true, mode: 0o700 });

  for (const definition of demoKeys) {
    const privatePath = resolve(outputDirectory, definition.privateFile);
    const publicPath = resolve(outputDirectory, definition.publicFile);

    if (existsSync(privatePath) && existsSync(publicPath)) {
      console.log(`${definition.name}: existing key pair preserved`);
      continue;
    }

    const keyPair = generateEd25519KeyPair();
    writeFileSync(privatePath, keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }), {
      mode: 0o600,
    });
    writeFileSync(publicPath, keyPair.publicKey.export({ type: 'spki', format: 'pem' }), {
      mode: 0o644,
    });
    console.log(`${definition.name}: generated key pair`);
  }
}

generateDemoKeys();
