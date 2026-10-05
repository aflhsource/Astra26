/**
 * TRUST-PASS DOWNTIME-PASS: QR Payload Serialization & Parsing
 *
 * Implements compact, URL-safe Base64 encoding for QR code payloads.
 *
 * SECURITY CONCEPT:
 * The QR code is a transport carrier, NOT the security.
 * The Ed25519 digital signature within the payload is the security.
 */

'use strict';

const PROTOCOL_PREFIX = 'TP1.';

/**
 * Encodes a signed safety card into a compact QR-friendly string.
 * Uses URL-safe Base64 (RFC 4648 §5).
 *
 * @param {Object} signedCard The signed safety card object.
 * @returns {string} QR payload string prefixed with 'TP1.'.
 */
function encodeQRPayload(signedCard) {
  if (!signedCard || typeof signedCard !== 'object') {
    throw new TypeError('Signed safety card must be an object');
  }

  const jsonStr = JSON.stringify(signedCard);
  const base64Url = Buffer.from(jsonStr, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  return `${PROTOCOL_PREFIX}${base64Url}`;
}

const MAX_QR_PAYLOAD_LENGTH = 64 * 1024; // 64 KB maximum buffer

/**
 * Decodes a raw QR payload string into a safety card object.
 * Safe against malformed inputs, oversized buffers, and crashes.
 *
 * @param {string} qrPayload The scanned string from the QR code.
 * @returns {{ success: boolean, card?: Object, error?: string }}
 */
function decodeQRPayload(qrPayload) {
  if (typeof qrPayload !== 'string' || !qrPayload.trim()) {
    return {
      success: false,
      error: 'Empty or non-string QR payload'
    };
  }

  const trimmed = qrPayload.trim();

  // Defensive Check: Prevent memory exhaustion DoS via oversized payload
  if (trimmed.length > MAX_QR_PAYLOAD_LENGTH) {
    return {
      success: false,
      error: `QR payload exceeds maximum safe buffer size (${MAX_QR_PAYLOAD_LENGTH} bytes)`
    };
  }

  let base64UrlContent = trimmed;

  if (trimmed.startsWith(PROTOCOL_PREFIX)) {
    base64UrlContent = trimmed.substring(PROTOCOL_PREFIX.length);
  } else if (trimmed.startsWith('TP1:')) {
    base64UrlContent = trimmed.substring(4);
  }

  try {
    // Restore base64 padding and standard characters
    let base64 = base64UrlContent
      .replace(/-/g, '+')
      .replace(/_/g, '/');

    while (base64.length % 4 !== 0) {
      base64 += '=';
    }

    const jsonStr = Buffer.from(base64, 'base64').toString('utf8');
    const card = JSON.parse(jsonStr);

    if (!card || typeof card !== 'object') {
      return {
        success: false,
        error: 'Parsed QR content is not a valid JSON object'
      };
    }

    return {
      success: true,
      card
    };
  } catch (err) {
    return {
      success: false,
      error: `Malformed QR payload: ${err.message}`
    };
  }
}

module.exports = {
  PROTOCOL_PREFIX,
  encodeQRPayload,
  decodeQRPayload
};
