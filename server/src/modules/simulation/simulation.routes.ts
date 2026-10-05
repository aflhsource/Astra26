import { Router } from 'express';
import { validate } from '../../middleware/validate.js';
import { runDemoScenarioController } from './simulation.controller.js';
import { demoScenarioSchema } from './simulation.schema.js';

export const simulationRoutes = Router();
simulationRoutes.post('/:scenario', validate(demoScenarioSchema), runDemoScenarioController);
