import { Router } from 'express';
import { dashboardSummaryController } from './dashboard.controller.js';

export const dashboardRoutes = Router();
dashboardRoutes.get('/summary', dashboardSummaryController);
