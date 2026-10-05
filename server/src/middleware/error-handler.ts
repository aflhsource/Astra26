import type { ErrorRequestHandler } from 'express';

export const errorHandler: ErrorRequestHandler = (error, _req, res, _next) => {
  console.error(JSON.stringify({ level: 'error', event: 'request_failed', error: String(error) }));
  res.status(500).json({
    success: false,
    error: { code: 'INTERNAL_ERROR', message: 'An internal server error occurred' },
    requestId: res.locals.requestId,
  });
};
