import type { Request, Response } from 'express';
import { createSource, getSourceById, listSources, updateSourceStatus } from './source.service.js';
import type { CreateSourceRequest } from './source.schema.js';
import type { SourceDocument } from './source.model.js';

export async function createSourceController(req: Request, res: Response): Promise<void> {
  try {
    const source = await createSource(req.body as CreateSourceRequest);
    res.status(201).json({ success: true, data: serializeSource(source) });
  } catch (error: unknown) {
    sendSourceError(error, res);
  }
}

export async function listSourcesController(_req: Request, res: Response): Promise<void> {
  try {
    const sources = await listSources();
    res.json({ success: true, data: sources.map(serializeSource) });
  } catch (error: unknown) {
    sendSourceError(error, res);
  }
}

export async function getSourceController(req: Request, res: Response): Promise<void> {
  try {
    const source = await getSourceById(getSourceId(req));
    res.json({ success: true, data: serializeSource(source) });
  } catch (error: unknown) {
    sendSourceError(error, res);
  }
}

export async function updateSourceStatusController(req: Request, res: Response): Promise<void> {
  try {
    const source = await updateSourceStatus(getSourceId(req), req.body.status);
    res.json({ success: true, data: serializeSource(source) });
  } catch (error: unknown) {
    sendSourceError(error, res);
  }
}

function getSourceId(req: Request): string {
  const value = req.params.sourceId;
  return Array.isArray(value) ? (value[0] ?? '') : (value ?? '');
}

function serializeSource(source: SourceDocument) {
  return {
    sourceId: source.sourceId,
    name: source.name,
    role: source.role,
    type: source.type,
    status: source.status,
    keyId: source.keyId,
    publicKey: source.publicKey,
    allowedTransformations: source.allowedTransformations,
    createdAt: source.createdAt,
    updatedAt: source.updatedAt,
  };
}

function sendSourceError(error: unknown, res: Response): void {
  if (isSourceServiceError(error)) {
    res.status(error.statusCode).json({
      success: false,
      error: { code: error.code, message: error.message },
      requestId: res.locals.requestId,
    });
    return;
  }
  res.status(500).json({
    success: false,
    error: { code: 'INTERNAL_ERROR', message: 'Unable to process source registry request' },
    requestId: res.locals.requestId,
  });
}

function isSourceServiceError(
  error: unknown,
): error is { code: string; message: string; statusCode: number } {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    'message' in error &&
    'statusCode' in error
  );
}
