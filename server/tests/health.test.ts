import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';

describe('GET /api/v1/health', () => {
  it('returns a structured degraded response when MongoDB is not connected', async () => {
    const response = await request(createApp()).get('/api/v1/health');

    expect(response.status).toBe(503);
    expect(response.body.success).toBe(false);
    expect(response.body.data.service).toBe('trust-pass-api');
    expect(response.body.data.database).toBe('disconnected');
    expect(response.headers['x-request-id']).toBeDefined();
  });
});
