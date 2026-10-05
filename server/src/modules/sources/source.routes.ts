import { Router } from 'express';
import { validate } from '../../middleware/validate.js';
import {
  createSourceController,
  getSourceController,
  listSourcesController,
  updateSourceStatusController,
} from './source.controller.js';
import {
  createSourceSchema,
  listSourcesSchema,
  sourceIdSchema,
  updateSourceStatusSchema,
} from './source.schema.js';

export const sourceRoutes = Router();

sourceRoutes.get('/', validate(listSourcesSchema), listSourcesController);
sourceRoutes.get('/:sourceId', validate(sourceIdSchema), getSourceController);
sourceRoutes.post('/', validate(createSourceSchema), createSourceController);
sourceRoutes.patch(
  '/:sourceId/status',
  validate(updateSourceStatusSchema),
  updateSourceStatusController,
);
