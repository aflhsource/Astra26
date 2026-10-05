import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import { env, corsOrigins } from './config/env.js';
import { isDatabaseConnected } from './database/connection.js';
import { errorHandler } from './middleware/error-handler.js';
import { apiRateLimit } from './middleware/rate-limit.js';
import { requestId } from './middleware/request-id.js';
import { sourceRoutes } from './modules/sources/source.routes.js';

export function createApp() {
  const app = express();

  app.disable('x-powered-by');
  app.use(helmet());
  app.use(cors({ origin: corsOrigins }));
  app.use(express.json({ limit: env.BODY_LIMIT }));
  app.use(requestId);
  app.use(apiRateLimit);

  app.use('/api/v1/sources', sourceRoutes);

  app.get('/api/v1/health', (_req, res) => {
    const database = isDatabaseConnected() ? 'connected' : 'disconnected';
    res.status(database === 'connected' ? 200 : 503).json({
      success: database === 'connected',
      data: {
        service: 'trust-pass-api',
        status: database === 'connected' ? 'ok' : 'degraded',
        database,
        timestamp: new Date().toISOString(),
      },
      ...(database === 'connected'
        ? {}
        : { error: { code: 'DATABASE_UNAVAILABLE', message: 'Database is unavailable' } }),
    });
  });

  app.use(errorHandler);
  return app;
}
