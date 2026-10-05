import type { Request, Response } from 'express';
import { getTrustPassByTransactionId, revokeTrustPass } from './trust-pass.service.js';

export async function getTrustPassController(req: Request, res: Response): Promise<void> {
  const transactionId = Array.isArray(req.params.transactionId)
    ? (req.params.transactionId[0] ?? '')
    : (req.params.transactionId ?? '');
  const pass = await getTrustPassByTransactionId(transactionId);
  if (!pass) {
    res.status(404).json({
      success: false,
      error: { code: 'TRUST_PASS_INVALID', message: 'Trust Pass was not found' },
      requestId: res.locals.requestId,
    });
    return;
  }
  res.json({ success: true, data: pass.toObject() });
}

export async function revokeTrustPassController(req: Request, res: Response): Promise<void> {
  const transactionId = Array.isArray(req.params.transactionId)
    ? (req.params.transactionId[0] ?? '')
    : (req.params.transactionId ?? '');
  const pass = await revokeTrustPass(transactionId);
  if (!pass) {
    res.status(404).json({
      success: false,
      error: { code: 'TRUST_PASS_INVALID', message: 'Trust Pass was not found' },
      requestId: res.locals.requestId,
    });
    return;
  }
  res.json({ success: true, data: pass.toObject() });
}
