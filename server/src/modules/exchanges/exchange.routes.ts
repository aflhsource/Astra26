import { Router } from 'express';
import { validate } from '../../middleware/validate.js';
import {
  createExchangeController,
  getExchangeController,
  listExchangesController,
} from './exchange.controller.js';
import {
  createExchangeSchema,
  exchangeTransactionSchema,
  listExchangesSchema,
} from './exchange.schema.js';

export const exchangeRoutes = Router();

exchangeRoutes.get('/', validate(listExchangesSchema), listExchangesController);
exchangeRoutes.get('/:transactionId', validate(exchangeTransactionSchema), getExchangeController);
exchangeRoutes.post('/', validate(createExchangeSchema), createExchangeController);
