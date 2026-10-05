/**
 * TRUST-PASS DOWNTIME-PASS Module Entrypoint
 */

'use strict';

const {
  createSafetyCard,
  verifySafetyCard,
  validateSyntheticPatientData
} = require('./card');

const {
  PROTOCOL_PREFIX,
  encodeQRPayload,
  decodeQRPayload
} = require('./qr');

const {
  verifySafetyCardLocally
} = require('./offline-verifier');

module.exports = {
  createSafetyCard,
  verifySafetyCard,
  validateSyntheticPatientData,
  PROTOCOL_PREFIX,
  encodeQRPayload,
  decodeQRPayload,
  verifySafetyCardLocally
};
