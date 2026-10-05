import { Router } from 'express';
import { getTrustPassController, revokeTrustPassController } from './trust-pass.controller.js';

export const trustPassRoutes = Router();
trustPassRoutes.get('/:transactionId', getTrustPassController);
trustPassRoutes.post('/:transactionId/revoke', revokeTrustPassController);
