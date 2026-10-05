import type { NextFunction, Request, Response } from 'express';
import type { ZodType } from 'zod';

export function validate<T>(schema: ZodType<T>) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const result = schema.safeParse({ body: req.body, params: req.params, query: req.query });
    if (!result.success) {
      res.status(400).json({
        success: false,
        error: { code: 'VALIDATION_ERROR', message: 'Request validation failed' },
        requestId: res.locals.requestId,
      });
      return;
    }
    next();
  };
}
