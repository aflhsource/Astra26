/**
 * TRUST-PASS Cryptographic Foundation
 * Ed25519 Key Management & Fingerprinting Helpers
 *
 * NOTE: For development, testing, and demonstration purposes only.
 * Production hospital infrastructure requires Hardware Security Modules (HSM),
 * KMS, or secure vault key management with automated rotation.
 * NEVER commit private keys or hardcode them in production code.
 */

'use strict';

const crypto = require('node:crypto');
const { hashData } = require('./hash');

/**
 * Generates an Ed25519 asymmetric cryptographic keypair.
 * @param {Object} [options]
 * @param {'pem'|'der'} [options.format='pem'] Key export format.
 * @returns {{ publicKey: string, privateKey: string, keyId: string, algorithm: string }}
 */
function generateKeyPair(options = {}) {
  const format = options.format || 'pem';

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

  const pubKeyExport = publicKey.export({
    type: 'spki',
    format: format === 'pem' ? 'pem' : 'der'
  });

  const privKeyExport = privateKey.export({
    type: 'pkcs8',
    format: format === 'pem' ? 'pem' : 'der'
  });

  const pubKeyFormatted = format === 'pem' ? pubKeyExport.toString() : pubKeyExport;
  const privKeyFormatted = format === 'pem' ? privKeyExport.toString() : privKeyExport;

  // Fingerprint the public key to create a unique keyId
  const keyId = computeKeyId(pubKeyFormatted);

  return {
    algorithm: 'Ed25519',
    keyId,
    publicKey: pubKeyFormatted,
    privateKey: privKeyFormatted
  };
}

/**
 * Computes a deterministic key identifier (fingerprint) from a public key.
 * @param {string|Buffer} publicKey Public key in PEM or SPKI format.
 * @returns {string} Key identifier string (e.g., 'key-a1b2c3d4...').
 */
function computeKeyId(publicKey) {
  if (!publicKey) {
    throw new Error('Public key is required to compute keyId');
  }
  const cleanKey = typeof publicKey === 'string' ? publicKey.trim() : publicKey;
  return 'key-' + hashData(cleanKey, { encoding: 'hex' }).substring(0, 16);
}

module.exports = {
  generateKeyPair,
  computeKeyId
};
