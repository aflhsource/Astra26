import type { ExchangeRecord } from '../exchanges/exchange.types.js';

export const demoScenarios = [
  'clean',
  'valid-transformation',
  'tamper',
  'replay',
  'expired',
  'unknown-source',
  'unauthorized-transformation',
  'context-mismatch',
] as const;

export type DemoScenario = (typeof demoScenarios)[number];

export interface DemoScenarioResult {
  scenario: DemoScenario;
  exchange: ExchangeRecord;
  attempts?: ExchangeRecord[];
  evidence: {
    expected: string;
    received: string;
  };
}
