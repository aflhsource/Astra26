import type { Request, Response } from 'express';
import { getDashboardSummary } from './dashboard.service.js';

export async function dashboardSummaryController(_req: Request, res: Response): Promise<void> {
  res.json({ success: true, data: await getDashboardSummary() });
}
