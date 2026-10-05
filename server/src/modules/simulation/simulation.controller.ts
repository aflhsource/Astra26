import type { Request, Response } from 'express';
import { runDemoScenario } from './simulation.service.js';
import type { DemoScenario } from './simulation.types.js';

export async function runDemoScenarioController(req: Request, res: Response): Promise<void> {
  const { scenario } = req.params as { scenario: DemoScenario };
  const result = await runDemoScenario(scenario);
  res.json({ success: true, data: result });
}
