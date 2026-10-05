import type { ExchangeEnvelope } from '../exchanges/exchange.types.js';

export interface ContextResult {
  valid: boolean;
  reasonCodes: string[];
}

export function validateContext(exchange: ExchangeEnvelope): ContextResult {
  const reasonCodes: string[] = [];
  if (exchange.context.patientRef !== exchange.payload.patientRef) {
    reasonCodes.push('CONTEXT_MISMATCH');
  }
  if (exchange.context.encounterRef !== exchange.payload.encounterRef) {
    reasonCodes.push('CONTEXT_MISMATCH');
  }
  if (exchange.resourceType !== exchange.payload.resourceType) {
    reasonCodes.push('CONTEXT_MISMATCH');
  }
  return { valid: reasonCodes.length === 0, reasonCodes: [...new Set(reasonCodes)] };
}
