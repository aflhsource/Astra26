/**
 * TRUST-PASS Gemini LLM Security Explanation Adapter
 *
 * Calls Google Gemini REST API using native fetch (Node 18+) to produce
 * clinical explanations.
 * Falls back gracefully to the deterministic Mock adapter if no API key
 * is present or if the network request encounters errors.
 */

'use strict';

const { SYSTEM_PROMPT, buildAnalysisPrompt } = require('../prompt');
const { MockAIAdapter } = require('./mock');

class GeminiAIAdapter {
  /**
   * @param {Object} [config]
   * @param {string} [config.apiKey] Gemini API Key (optional, defaults to process.env.GEMINI_API_KEY)
   * @param {string} [config.model='gemini-2.0-flash'] Target model
   * @param {number} [config.timeoutMs=5000] Network timeout
   */
  constructor(config = {}) {
    this.name = 'gemini';
    this.apiKey = config.apiKey || process.env.GEMINI_API_KEY || process.env.AI_API_KEY || '';
    this.model = config.model || process.env.GEMINI_MODEL || 'gemini-2.0-flash';
    this.timeoutMs = config.timeoutMs || 5000;
    this.fallbackAdapter = new MockAIAdapter();
  }

  /**
   * Generates analysis via Gemini API, falling back to mock on failure.
   * @param {Object} input
   * @returns {Promise<{ explanation: string, recommendation: string }>}
   */
  async generateAnalysis(input) {
    if (!this.apiKey) {
      // Graceful fallback to deterministic mock when no key is configured
      return this.fallbackAdapter.generateAnalysis(input);
    }

    try {
      const promptText = buildAnalysisPrompt(input);
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(this.model)}:generateContent?key=${encodeURIComponent(this.apiKey)}`;

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: controller.signal,
        body: JSON.stringify({
          system_instruction: {
            parts: [{ text: SYSTEM_PROMPT }]
          },
          contents: [{
            parts: [{ text: promptText }]
          }],
          generationConfig: {
            response_mime_type: 'application/json',
            temperature: 0.2
          }
        })
      });

      clearTimeout(timer);

      if (!response.ok) {
        // Fallback on HTTP error
        return this.fallbackAdapter.generateAnalysis(input);
      }

      const data = await response.json();
      const rawText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
      if (!rawText) {
        return this.fallbackAdapter.generateAnalysis(input);
      }

      const parsed = JSON.parse(rawText);
      return {
        explanation: parsed.explanation || 'No explanation provided by model',
        recommendation: parsed.recommendation || 'Verify records with authoritative healthcare source'
      };
    } catch {
      // On network error or timeout, safely fall back to deterministic mock
      return this.fallbackAdapter.generateAnalysis(input);
    }
  }
}

module.exports = {
  GeminiAIAdapter
};
