/**
 * TRUST-PASS AI Security Analysis Module Entrypoint
 */

'use strict';

const { analyzeSecurityRisk, normalizeInput } = require('./analyzer');
const { MockAIAdapter } = require('./adapters/mock');
const { GeminiAIAdapter } = require('./adapters/gemini');
const { SYSTEM_PROMPT, buildAnalysisPrompt } = require('./prompt');

module.exports = {
  analyzeSecurityRisk,
  normalizeInput,
  MockAIAdapter,
  GeminiAIAdapter,
  SYSTEM_PROMPT,
  buildAnalysisPrompt
};
