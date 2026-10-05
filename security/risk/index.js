/**
 * TRUST-PASS Risk Module Entrypoint
 */

'use strict';

const { RULES, RISK_LEVELS, DISCLAIMER, getRiskLevel } = require('./rules');
const { calculateRiskScore } = require('./engine');

module.exports = {
  RULES,
  RISK_LEVELS,
  DISCLAIMER,
  getRiskLevel,
  calculateRiskScore
};
