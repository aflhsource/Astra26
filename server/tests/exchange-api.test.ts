import request from 'supertest';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const service = vi.hoisted(() => ({
  getExchangeRecord: vi.fn(),
  listExchangeRecords: vi.fn(),
  processExchange: vi.fn(),
}));

vi.mock('../src/modules/exchanges/exchange.service.js', () => service);

import { createApp } from '../src/app.js';

describe('exchange API', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('rejects malformed envelopes before calling the service', async () => {
    const response = await request(createApp())
      .post('/api/v1/exchanges')
      .send({ transactionId: 'BAD' });

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
    expect(service.processExchange).not.toHaveBeenCalled();
  });

  it('returns backend-calculated verification data', async () => {
    service.processExchange.mockResolvedValue({
      transactionId: 'TX-API-001',
      source: { sourceId: 'LAB-A', keyId: 'lab-a-key-1' },
      resourceType: 'Observation',
      context: {
        patientRef: 'PAT-1001',
        encounterRef: 'ENC-1001',
        purpose: 'clinical-decision-support',
        audience: 'CLINICAL-AI',
      },
      payload: {
        resourceType: 'Observation',
        patientRef: 'PAT-1001',
        encounterRef: 'ENC-1001',
        data: { value: 120 },
      },
      issuedAt: '2026-10-05T12:00:00.000Z',
      expiresAt: '2026-10-05T12:05:00.000Z',
      sequence: 1,
      nonce: 'nonce-api-001',
      payloadHash: 'a'.repeat(64),
      provenance: { originSourceId: 'LAB-A', originHash: 'a'.repeat(64), transformations: [] },
      signature: 'synthetic-signature',
      verification: {
        decision: 'ALLOW',
        reasonCodes: [],
        checks: {
          schemaValid: true,
          sourceKnown: true,
          keyKnown: true,
          hashValid: true,
          signatureValid: true,
          sourceActive: true,
        },
        sourceId: 'LAB-A',
        keyId: 'lab-a-key-1',
        payloadHash: 'a'.repeat(64),
        verifiedAt: '2026-10-05T12:00:00.000Z',
      },
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const response = await request(createApp())
      .post('/api/v1/exchanges')
      .send({
        transactionId: 'TX-API-001',
        source: { sourceId: 'LAB-A', keyId: 'lab-a-key-1' },
        resourceType: 'Observation',
        context: {
          patientRef: 'PAT-1001',
          encounterRef: 'ENC-1001',
          purpose: 'clinical-decision-support',
          audience: 'CLINICAL-AI',
        },
        payload: {
          resourceType: 'Observation',
          patientRef: 'PAT-1001',
          encounterRef: 'ENC-1001',
          data: { value: 120 },
        },
        issuedAt: '2026-10-05T12:00:00.000Z',
        expiresAt: '2026-10-05T12:05:00.000Z',
        sequence: 1,
        nonce: 'nonce-api-001',
        payloadHash: 'a'.repeat(64),
        provenance: { originSourceId: 'LAB-A', originHash: 'a'.repeat(64), transformations: [] },
        signature: 'synthetic-signature',
      });

    expect(response.status).toBe(200);
    expect(response.body.data.verification.decision).toBe('ALLOW');
  });
});
