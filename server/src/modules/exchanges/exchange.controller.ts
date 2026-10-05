import type { Request, Response } from 'express';
import {
  ExchangeNotFoundError,
  ExchangeServiceError,
  getExchangeRecord,
  listExchangeRecords,
  processExchange,
} from './exchange.service.js';
import type { CreateExchangeInput } from './exchange.schema.js';
import type { ExchangeRecord } from './exchange.types.js';

export async function createExchangeController(req: Request, res: Response): Promise<void> {
  try {
    const exchange = await processExchange(req.body as CreateExchangeInput);
    res.json({ success: true, data: serializeExchange(exchange) });
  } catch (error: unknown) {
    sendExchangeError(error, res);
  }
}

export async function listExchangesController(_req: Request, res: Response): Promise<void> {
  try {
    const exchanges = await listExchangeRecords();
    res.json({ success: true, data: exchanges.map(serializeExchange) });
  } catch (error: unknown) {
    sendExchangeError(error, res);
  }
}

export async function getExchangeController(req: Request, res: Response): Promise<void> {
  try {
    const transactionId = Array.isArray(req.params.transactionId)
      ? (req.params.transactionId[0] ?? '')
      : (req.params.transactionId ?? '');
    const exchange = await getExchangeRecord(transactionId);
    res.json({ success: true, data: serializeExchange(exchange) });
  } catch (error: unknown) {
    sendExchangeError(error, res);
  }
}

function serializeExchange(exchange: ExchangeRecord) {
  return {
    transactionId: exchange.transactionId,
    source: exchange.source,
    resourceType: exchange.resourceType,
    context: exchange.context,
    payload: exchange.payload,
    issuedAt: exchange.issuedAt,
    expiresAt: exchange.expiresAt,
    sequence: exchange.sequence,
    nonce: exchange.nonce,
    payloadHash: exchange.payloadHash,
    provenance: exchange.provenance,
    verification: exchange.verification,
    signature: exchange.signature,
    createdAt: exchange.createdAt,
    updatedAt: exchange.updatedAt,
  };
}

function sendExchangeError(error: unknown, res: Response): void {
  if (error instanceof ExchangeServiceError) {
    res.status(error.statusCode).json({
      success: false,
      error: { code: error.code, message: error.message },
      requestId: res.locals.requestId,
    });
    return;
  }
  if (error instanceof ExchangeNotFoundError) {
    res.status(error.statusCode).json({
      success: false,
      error: { code: error.code, message: error.message },
      requestId: res.locals.requestId,
    });
    return;
  }
  res.status(500).json({
    success: false,
    error: { code: 'INTERNAL_ERROR', message: 'Unable to process exchange request' },
    requestId: res.locals.requestId,
  });
}
