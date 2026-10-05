import request from 'supertest';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { SourceDocument } from '../src/modules/sources/source.model.js';
import { createApp } from '../src/app.js';

const service = vi.hoisted(() => ({
  createSource: vi.fn(),
  getSourceById: vi.fn(),
  listSources: vi.fn(),
  updateSourceStatus: vi.fn(),
}));

vi.mock('../src/modules/sources/source.service.js', () => service);

const source = {
  sourceId: 'LAB-A',
  name: 'Laboratory A',
  role: 'SOURCE',
  type: 'LAB',
  status: 'ACTIVE',
  keyId: 'lab-a-key-1',
  publicKey: '-----BEGIN PUBLIC KEY----- synthetic -----END PUBLIC KEY-----',
  allowedTransformations: [],
  createdAt: new Date('2026-10-05T00:00:00.000Z'),
  updatedAt: new Date('2026-10-05T00:00:00.000Z'),
} as unknown as SourceDocument;

describe('source registry API', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('creates a source and never returns private key material', async () => {
    service.createSource.mockResolvedValue(source);

    const response = await request(createApp()).post('/api/v1/sources').send({
      sourceId: 'LAB-A',
      name: 'Laboratory A',
      role: 'SOURCE',
      type: 'LAB',
      status: 'ACTIVE',
      keyId: 'lab-a-key-1',
      publicKey: source.publicKey,
      allowedTransformations: [],
    });

    expect(response.status).toBe(201);
    expect(response.body.success).toBe(true);
    expect(response.body.data.sourceId).toBe('LAB-A');
    expect(response.body.data.privateKey).toBeUndefined();
  });

  it('rejects invalid source roles before database access', async () => {
    const response = await request(createApp()).post('/api/v1/sources').send({
      sourceId: 'BAD-SOURCE',
      name: 'Invalid Source',
      role: 'UNTRUSTED',
      type: 'EHR',
      status: 'ACTIVE',
      keyId: 'bad-key-1',
      publicKey: source.publicKey,
      allowedTransformations: [],
    });

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
    expect(service.createSource).not.toHaveBeenCalled();
  });

  it('returns a structured not-found response', async () => {
    service.getSourceById.mockRejectedValue({
      code: 'SOURCE_NOT_FOUND',
      message: 'Source was not found',
      statusCode: 404,
    });

    const response = await request(createApp()).get('/api/v1/sources/MISSING-SOURCE');

    expect(response.status).toBe(404);
    expect(response.body).toMatchObject({
      success: false,
      error: { code: 'SOURCE_NOT_FOUND' },
    });
    expect(response.body.requestId).toBeDefined();
  });

  it('updates a source status', async () => {
    service.updateSourceStatus.mockResolvedValue({ ...source, status: 'SUSPENDED' });

    const response = await request(createApp())
      .patch('/api/v1/sources/LAB-A/status')
      .send({ status: 'SUSPENDED' });

    expect(response.status).toBe(200);
    expect(response.body.data.status).toBe('SUSPENDED');
  });
});
