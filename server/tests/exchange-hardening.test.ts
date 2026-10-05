import { describe, expect, it } from 'vitest';
import { ExchangeModel } from '../src/modules/exchanges/exchange.model.js';

describe('exchange replay-protection indexes', () => {
  it('defines unique transaction and source-nonce indexes', () => {
    const indexes = ExchangeModel.schema.indexes();

    expect(indexes).toContainEqual([{ transactionId: 1 }, { unique: true }]);
    expect(indexes).toContainEqual([{ nonce: 1, 'source.sourceId': 1 }, { unique: true }]);
  });
});
