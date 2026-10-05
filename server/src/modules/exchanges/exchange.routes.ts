import { Router } from 'express';
import { validate } from '../../middleware/validate.js';
import {
  createExchangeController,
  getExchangeController,
  listExchangesController,
  reviewExchangeController,
} from './exchange.controller.js';
import {
  createExchangeSchema,
  exchangeTransactionSchema,
  listExchangesSchema,
  exchangeDecisionSchema,
} from './exchange.schema.js';

export const exchangeRoutes = Router();

exchangeRoutes.get('/', validate(listExchangesSchema), listExchangesController);
exchangeRoutes.get('/:transactionId', validate(exchangeTransactionSchema), getExchangeController);
exchangeRoutes.post('/', validate(createExchangeSchema), createExchangeController);
exchangeRoutes.post(
  '/:transactionId/decision',
  validate(exchangeDecisionSchema),
  reviewExchangeController,
);
