import type { KeyLike, KeyObject } from 'node:crypto';

export type CryptoKey = KeyLike;

export interface Ed25519KeyPair {
  privateKey: KeyObject;
  publicKey: KeyObject;
}
