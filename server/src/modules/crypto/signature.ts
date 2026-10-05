import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign as signBytes,
  verify as verifyBytes,
} from 'node:crypto';
import { canonicalize } from './canonicalize.js';
import type { CryptoKey, Ed25519KeyPair } from './crypto.types.js';

function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(canonicalize(value), 'utf8');
}

export function generateEd25519KeyPair(): Ed25519KeyPair {
  return generateKeyPairSync('ed25519');
}

export function sign(value: unknown, privateKey: CryptoKey): string {
  return signBytes(null, canonicalBytes(value), privateKey).toString('base64url');
}

export function verify(value: unknown, signature: string, publicKey: CryptoKey): boolean {
  try {
    if (
      typeof signature !== 'string' ||
      signature.length === 0 ||
      !/^[A-Za-z0-9_-]+$/.test(signature)
    )
      return false;
    const signatureBytes = Buffer.from(signature, 'base64url');
    if (signatureBytes.length !== 64 || signatureBytes.toString('base64url') !== signature)
      return false;
    return verifyBytes(null, canonicalBytes(value), publicKey, signatureBytes);
  } catch {
    return false;
  }
}

export function fingerprintPublicKey(publicKey: CryptoKey): string {
  const key =
    typeof publicKey === 'string' || Buffer.isBuffer(publicKey)
      ? createPublicKey(publicKey)
      : publicKey;
  const der = key.export({ type: 'spki', format: 'der' });
  return `key-${createHash('sha256').update(der).digest('hex').slice(0, 16)}`;
}
