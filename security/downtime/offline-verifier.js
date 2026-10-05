/**
 * TRUST-PASS DOWNTIME-PASS: Standalone Offline Verifier
 *
 * Verifies signed safety cards completely client-side.
 * REQUIRES NO:
 * - Express / backend server
 * - MongoDB / database
 * - Internet / WAN connectivity
 *
 * All that is needed is the trusted healthcare public verification key.
 */

'use strict';

const { decodeQRPayload } = require('./qr');
const { verifySafetyCard } = require('./card');

/**
 * Deterministically verifies a patient safety card locally without backend or internet.
 *
 * @param {string|Object} payload Raw QR string (TP1....), JSON string, or parsed card object.
 * @param {string} trustedPublicKey Ed25519 public key in PEM format.
 * @param {Object} [options]
 * @param {boolean} [options.allowExpired=false]
 * @returns {{
 *   valid: boolean,
 *   status: 'VALID'|'TAMPERED'|'INVALID'|'EXPIRED',
 *   offline: true,
 *   reason: string,
 *   patient?: Object,
 *   issuer?: string,
 *   cardId?: string,
 *   keyId?: string,
 *   isExpired?: boolean
 * }}
 */
function verifySafetyCardLocally(payload, trustedPublicKey, options = {}) {
  let cardObject;

  // Step 1: Decode payload if provided as string
  if (typeof payload === 'string') {
    const trimmed = payload.trim();
    if (trimmed.startsWith('TP1.') || trimmed.startsWith('TP1:')) {
      const decoded = decodeQRPayload(trimmed);
      if (!decoded.success) {
        return {
          valid: false,
          status: 'TAMPERED',
          offline: true,
          reason: `Invalid or corrupted QR payload: ${decoded.error}`
        };
      }
      cardObject = decoded.card;
    } else {
      // Try parsing as standard JSON string
      try {
        cardObject = JSON.parse(trimmed);
      } catch {
        return {
          valid: false,
          status: 'INVALID',
          offline: true,
          reason: 'Payload is neither a valid TP1 QR string nor valid JSON'
        };
      }
    }
  } else if (payload && typeof payload === 'object') {
    cardObject = payload;
  } else {
    return {
      valid: false,
      status: 'INVALID',
      offline: true,
      reason: 'Missing payload'
    };
  }

  // Step 2: Validate against trusted public key
  const verification = verifySafetyCard(cardObject, trustedPublicKey, options);

  return {
    ...verification,
    offline: true
  };
}

module.exports = {
  verifySafetyCardLocally
};
