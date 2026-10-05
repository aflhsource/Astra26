import { Router } from 'express';
import { validate } from '../../middleware/validate.js';
import { consumeDownstreamController } from './downstream.controller.js';
import { consumeSchema } from './downstream.schema.js';

export const downstreamRoutes = Router();
downstreamRoutes.post('/consume', validate(consumeSchema), consumeDownstreamController);
