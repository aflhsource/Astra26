import { ExchangeModel, type ExchangeDocument } from './exchange.model.js';
import type { ExchangeRecord } from './exchange.types.js';

export async function findExchangeByTransactionId(
  transactionId: string,
): Promise<ExchangeDocument | null> {
  return ExchangeModel.findOne({ transactionId }).exec();
}

export async function findExchangeBySourceAndNonce(
  sourceId: string,
  nonce: string,
): Promise<ExchangeDocument | null> {
  return ExchangeModel.findOne({
    'source.sourceId': sourceId,
    nonce,
    'verification.checks.hashValid': true,
    'verification.checks.signatureValid': true,
  }).exec();
}

export async function findLatestSequenceBySource(
  sourceId: string,
): Promise<ExchangeDocument | null> {
  return ExchangeModel.findOne({
    'source.sourceId': sourceId,
    'verification.checks.hashValid': true,
    'verification.checks.signatureValid': true,
  })
    .sort({ sequence: -1, createdAt: -1 })
    .exec();
}

export async function insertExchange(record: ExchangeRecord): Promise<ExchangeDocument> {
  return ExchangeModel.create(record);
}

export async function findExchanges(): Promise<ExchangeDocument[]> {
  return ExchangeModel.find().sort({ createdAt: -1 }).exec();
}
