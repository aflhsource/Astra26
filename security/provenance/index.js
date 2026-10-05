/**
 * TRUST-PASS Provenance Module Entrypoint
 */

'use strict';

const { createProvenanceRecord, appendTransformation } = require('./record');
const { verifyIntegrity } = require('./verify');

module.exports = {
  createProvenanceRecord,
  appendTransformation,
  verifyIntegrity
};
