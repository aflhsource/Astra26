/**
 * TRUST-PASS Cryptographic Foundation
 * SHA-256 Integrity Digest Utility
 *
 * Produces cryptographic digests of canonicalized payloads and verifies
 * integrity using timing-safe comparisons to prevent timing side-channels.
 */

'use strict';

const crypto = require('node:crypto');
const { canonicalize } = require('./canonicalize');

/**
 * Calculates a SHA-256 cryptographic digest of data.
 * @param {*} data Object, string, or Buffer. Objects are automatically canonicalized.
 * @param {Object} [options]
 * @param {'hex'|'base64'|'base64url'} [options.encoding='hex'] Output digest format.
 * @returns {string} The SHA-256 hash string.
 */
function hashData(data, options = {}) {
  const encoding = options.encoding || 'hex';
  let buffer;

  if (Buffer.isBuffer(data)) {
    buffer = data;
  } else if (typeof data === 'string') {
    buffer = Buffer.from(data, 'utf8');
  } else if (typeof data === 'object' && data !== null) {
    const canonicalStr = canonicalize(data);
    buffer = Buffer.from(canonicalStr, 'utf8');
  } else {
    buffer = Buffer.from(String(data), 'utf8');
  }

  return crypto.createHash('sha256').update(buffer).digest(encoding);
}

/**
 * Verifies that data matches an expected SHA-256 hash using constant-time comparison.
 * @param {*} data The data payload.
 * @param {string} expectedHash The expected SHA-256 hash.
 * @param {Object} [options]
 * @param {'hex'|'base64'|'base64url'} [options.encoding='hex'] Hash encoding.
 * @returns {{ valid: boolean, reason: string, calculatedHash?: string }} Structured verification result.
 */
function verifyHash(data, expectedHash, options = {}) {
  if (typeof expectedHash !== 'string' || !expectedHash.trim()) {
    return {
      valid: false,
      reason: 'Missing or empty expected hash'
    };
  }

  try {
    const encoding = options.encoding || 'hex';
    const calculatedHash = hashData(data, options);
    const cleanExpected = expectedHash.trim();

    // For hex digests, normalize case-insensitivity deterministically
    const normalizedCalc = encoding === 'hex' ? calculatedHash.toLowerCase() : calculatedHash;
    const normalizedExp = encoding === 'hex' ? cleanExpected.toLowerCase() : cleanExpected;

    const calculatedBuf = Buffer.from(normalizedCalc, 'utf8');
    const expectedBuf = Buffer.from(normalizedExp, 'utf8');

    if (calculatedBuf.length !== expectedBuf.length) {
      return {
        valid: false,
        reason: 'Hash length mismatch',
        calculatedHash
      };
    }

    const matches = crypto.timingSafeEqual(calculatedBuf, expectedBuf);
    return {
      valid: matches,
      reason: matches ? 'Hash matched' : 'Digest mismatch (payload modified)',
      calculatedHash
    };
  } catch (err) {
    return {
      valid: false,
      reason: `Hash verification error: ${err.message}`
    };
  }
}

module.exports = {
  hashData,
  verifyHash
};
