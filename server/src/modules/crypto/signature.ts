import { generateKeyPairSync, sign as signBytes, verify as verifyBytes } from 'node:crypto';
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
    return verifyBytes(null, canonicalBytes(value), publicKey, Buffer.from(signature, 'base64url'));
  } catch {
    return false;
  }
}
