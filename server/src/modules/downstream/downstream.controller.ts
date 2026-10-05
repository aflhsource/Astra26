import type { Request, Response } from 'express';
import { getExchangeRecord } from '../exchanges/exchange.service.js';
import { systemAudit } from '../audit/audit.service.js';
import { verifyForConsumption } from '../trust-pass/trust-pass.service.js';

export async function consumeDownstreamController(req: Request, res: Response): Promise<void> {
  const { transactionId, trustPassId, payload, audience, purpose } = req.body as {
    transactionId: string;
    trustPassId: string;
    payload: unknown;
    audience: string;
    purpose: string;
  };
  try {
    const exchange = await getExchangeRecord(transactionId);
    const result = await verifyForConsumption(
      { transactionId, trustPassId, payload, audience, purpose },
      exchange,
    );
    if (!result.allowed) {
      await systemAudit(
        transactionId,
        'DOWNSTREAM_DENIED',
        [result.reasonCode ?? 'DOWNSTREAM_CONSUMPTION_DENIED'],
        'QUARANTINE',
        exchange.payloadHash,
      );
      res.status(403).json({
        success: false,
        error: {
          code: 'DOWNSTREAM_CONSUMPTION_DENIED',
          message: result.reasonCode ?? 'Downstream consumption denied',
        },
        requestId: res.locals.requestId,
      });
      return;
    }
    await systemAudit(transactionId, 'DOWNSTREAM_CONSUMED', [], 'ALLOW', exchange.payloadHash);
    res.json({ success: true, data: { transactionId, consumed: true, decision: 'ALLOW' } });
  } catch (error: unknown) {
    const code =
      error instanceof Error && 'code' in error && error.code === 'EXCHANGE_NOT_FOUND'
        ? 'DOWNSTREAM_CONSUMPTION_DENIED'
        : 'DOWNSTREAM_CONSUMPTION_DENIED';
    res.status(403).json({
      success: false,
      error: { code, message: 'Downstream consumption denied' },
      requestId: res.locals.requestId,
    });
  }
}
