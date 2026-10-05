/**
 * TRUST-PASS Cryptographic Module Entrypoint
 */

'use strict';

const { canonicalize, canonicalizeValue } = require('./canonicalize');
const { hashData, verifyHash } = require('./hash');
const { generateKeyPair, computeKeyId } = require('./keys');
const { signData, verifyData } = require('./sign');

module.exports = {
  canonicalize,
  canonicalizeValue,
  hashData,
  verifyHash,
  generateKeyPair,
  computeKeyId,
  signData,
  verifyData
};
