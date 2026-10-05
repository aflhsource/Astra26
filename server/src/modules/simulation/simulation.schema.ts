import { z } from 'zod';
import { demoScenarios } from './simulation.types.js';

export const demoScenarioSchema = z.object({
  body: z.unknown().optional(),
  params: z.object({ scenario: z.enum(demoScenarios) }),
  query: z.object({}),
});
