import { ExchangeModel, type ExchangeDocument } from './exchange.model.js';
import type { ExchangeRecord } from './exchange.types.js';

export async function findExchangeByTransactionId(
  transactionId: string,
): Promise<ExchangeDocument | null> {
  return ExchangeModel.findOne({ transactionId }).exec();
}

export async function insertExchange(record: ExchangeRecord): Promise<ExchangeDocument> {
  return ExchangeModel.create(record);
}

export async function findExchanges(): Promise<ExchangeDocument[]> {
  return ExchangeModel.find().sort({ createdAt: -1 }).exec();
}
