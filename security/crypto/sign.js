/**
 * TRUST-PASS Cryptographic Foundation
 * Digital Signing & Verification using Ed25519
 *
 * Implements deterministic asymmetric digital signature generation and verification.
 * Digital signatures provide non-repudiation and integrity verification.
 */

'use strict';

const crypto = require('node:crypto');
const { canonicalize } = require('./canonicalize');
const { computeKeyId } = require('./keys');

/**
 * Signs arbitrary data using an Ed25519 private key.
 * @param {*} data Data payload (object, string, or Buffer). Objects are canonicalized deterministically.
 * @param {string|crypto.KeyObject} privateKey Ed25519 private key in PEM format or KeyObject.
 * @param {Object} [options]
 * @param {string} [options.keyId] Optional explicit key identifier.
 * @param {'base64'|'base64url'|'hex'} [options.encoding='base64'] Signature encoding.
 * @param {boolean} [options.includeCanonical=false] Whether to include canonical string in result.
 * @returns {{ signature: string, algorithm: string, keyId?: string, canonicalPayload?: string }}
 */
function signData(data, privateKey, options = {}) {
  if (!data && data !== 0 && data !== '') {
    throw new TypeError('Cannot sign null, undefined or empty data');
  }
  if (!privateKey) {
    throw new TypeError('Private key is required for digital signing');
  }

  const encoding = options.encoding || 'base64';
  let buffer;
  let canonicalStr;

  if (Buffer.isBuffer(data)) {
    buffer = data;
  } else if (typeof data === 'string') {
    buffer = Buffer.from(data, 'utf8');
    canonicalStr = data;
  } else if (typeof data === 'object') {
    canonicalStr = canonicalize(data);
    buffer = Buffer.from(canonicalStr, 'utf8');
  } else {
    canonicalStr = String(data);
    buffer = Buffer.from(canonicalStr, 'utf8');
  }

  // Node.js crypto.sign expects null as algorithm for Ed25519
  const keyObj = typeof privateKey === 'string'
    ? crypto.createPrivateKey({ key: privateKey, format: 'pem' })
    : privateKey;

  const rawSignature = crypto.sign(null, buffer, keyObj);
  const signature = rawSignature.toString(encoding);

  const result = {
    signature,
    algorithm: 'Ed25519',
    encoding
  };

  if (options.keyId) {
    result.keyId = options.keyId;
  }

  if (options.includeCanonical && canonicalStr !== undefined) {
    result.canonicalPayload = canonicalStr;
  }

  return result;
}

/**
 * Verifies an Ed25519 digital signature against a data payload and public key.
 * Never throws on malformed inputs; always returns a structured verification result.
 * @param {*} data Original data payload (object, string, or Buffer).
 * @param {string|Buffer} signature The signature to verify.
 * @param {string|crypto.KeyObject} publicKey Ed25519 public key in PEM format or KeyObject.
 * @param {Object} [options]
 * @param {'base64'|'base64url'|'hex'} [options.encoding='base64'] Signature encoding.
 * @returns {{ valid: boolean, reason: string, algorithm: string, error?: string }}
 */
function verifyData(data, signature, publicKey, options = {}) {
  const result = {
    valid: false,
    reason: '',
    algorithm: 'Ed25519'
  };

  if (data === null || data === undefined) {
    result.reason = 'Missing data payload';
    return result;
  }

  if (!signature) {
    result.reason = 'Missing signature';
    return result;
  }

  if (!publicKey) {
    result.reason = 'Missing public key';
    return result;
  }

  try {
    const encoding = options.encoding || 'base64';
    let buffer;

    if (Buffer.isBuffer(data)) {
      buffer = data;
    } else if (typeof data === 'string') {
      buffer = Buffer.from(data, 'utf8');
    } else if (typeof data === 'object') {
      const canonicalStr = canonicalize(data);
      buffer = Buffer.from(canonicalStr, 'utf8');
    } else {
      buffer = Buffer.from(String(data), 'utf8');
    }

    const keyObj = typeof publicKey === 'string'
      ? crypto.createPublicKey({ key: publicKey, format: 'pem' })
      : publicKey;

    const signatureBuf = Buffer.isBuffer(signature)
      ? signature
      : Buffer.from(signature, encoding);

    // Cryptographic Hardening: Ed25519 raw signatures are strictly 64 bytes
    if (signatureBuf.length !== 64) {
      result.valid = false;
      result.reason = `Invalid signature length (${signatureBuf.length} bytes; Ed25519 requires exactly 64 bytes)`;
      return result;
    }

    // Anti-Malleability Check: Reject signatures with extra trailing bytes or non-canonical base64 padding
    if (typeof signature === 'string') {
      const trimmed = signature.trim();
      if (encoding === 'base64') {
        const canonicalEncoded = signatureBuf.toString('base64');
        if (canonicalEncoded !== trimmed) {
          result.valid = false;
          result.reason = 'Signature malleability rejected: Non-canonical base64 encoding or extraneous bytes detected';
          return result;
        }
      }
    }

    const isValid = crypto.verify(null, buffer, keyObj, signatureBuf);

    if (isValid) {
      result.valid = true;
      result.reason = 'Signature verified';
    } else {
      result.valid = false;
      result.reason = 'Signature verification failed (tampered data or wrong key)';
    }

    return result;
  } catch (err) {
    result.valid = false;
    result.reason = 'Signature verification failed due to invalid signature or key format';
    result.error = err.message;
    return result;
  }
}

module.exports = {
  signData,
  verifyData
};
