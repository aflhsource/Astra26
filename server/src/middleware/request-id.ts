import type { RequestHandler } from 'express';
import { randomUUID } from 'node:crypto';

export const requestId: RequestHandler = (req, res, next) => {
  const id = req.header('X-Request-ID') ?? randomUUID();
  res.setHeader('X-Request-ID', id);
  res.locals.requestId = id;
  next();
};
