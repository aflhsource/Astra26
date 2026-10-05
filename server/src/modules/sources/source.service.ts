import {
  changeSourceStatus,
  findSourceById,
  findSources,
  insertSource,
} from './source.repository.js';
import type { SourceDocument } from './source.model.js';
import type { CreateSourceInput, SourceStatus } from './source.types.js';

export class SourceServiceError extends Error {
  public readonly code: 'SOURCE_ALREADY_EXISTS' | 'SOURCE_NOT_FOUND';
  public readonly statusCode: 404 | 409;

  public constructor(
    code: 'SOURCE_ALREADY_EXISTS' | 'SOURCE_NOT_FOUND',
    message: string,
    statusCode: 404 | 409,
  ) {
    super(message);
    this.name = 'SourceServiceError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

export async function createSource(input: CreateSourceInput): Promise<SourceDocument> {
  try {
    return await insertSource(input);
  } catch (error: unknown) {
    if (isDuplicateKeyError(error)) {
      throw new SourceServiceError(
        'SOURCE_ALREADY_EXISTS',
        'A source with this sourceId already exists',
        409,
      );
    }
    throw error;
  }
}

export async function getSourceById(sourceId: string): Promise<SourceDocument> {
  const source = await findSourceById(sourceId);
  if (!source) {
    throw new SourceServiceError('SOURCE_NOT_FOUND', 'Source was not found', 404);
  }
  return source;
}

export function listSources(): Promise<SourceDocument[]> {
  return findSources();
}

export async function updateSourceStatus(
  sourceId: string,
  status: SourceStatus,
): Promise<SourceDocument> {
  const source = await changeSourceStatus(sourceId, status);
  if (!source) {
    throw new SourceServiceError('SOURCE_NOT_FOUND', 'Source was not found', 404);
  }
  return source;
}

export async function getSourcePublicKey(sourceId: string): Promise<string> {
  const source = await getSourceById(sourceId);
  return source.publicKey;
}

function isDuplicateKeyError(error: unknown): error is { code: 11000 } {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 11000;
}
