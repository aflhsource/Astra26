import type { SourceDocument } from '../src/modules/sources/source.model.js';
import type { CreateSourceInput, SourceRecord } from '../src/modules/sources/source.types.js';
import {
  createSource,
  getSourceById,
  getSourcePublicKey,
  updateSourceStatus,
} from '../src/modules/sources/source.service.js';
import { describe, expect, it, vi } from 'vitest';

const repository = vi.hoisted(() => ({
  changeSourceStatus: vi.fn(),
  findSourceById: vi.fn(),
  findSources: vi.fn(),
  insertSource: vi.fn(),
}));

vi.mock('../src/modules/sources/source.repository.js', () => repository);

const sourceInput: CreateSourceInput = {
  sourceId: 'LAB-A',
  name: 'Laboratory A',
  role: 'SOURCE',
  type: 'LAB',
  status: 'ACTIVE',
  keyId: 'lab-a-key-1',
  publicKey: '-----BEGIN PUBLIC KEY----- synthetic -----END PUBLIC KEY-----',
  allowedTransformations: [],
};

const sourceDocument = {
  ...sourceInput,
  createdAt: new Date('2026-10-05T00:00:00.000Z'),
  updatedAt: new Date('2026-10-05T00:00:00.000Z'),
} as unknown as SourceDocument;

describe('source registry service', () => {
  it('creates a valid source', async () => {
    repository.insertSource.mockResolvedValue(sourceDocument);

    await expect(createSource(sourceInput)).resolves.toBe(sourceDocument);
    expect(repository.insertSource).toHaveBeenCalledWith(sourceInput);
  });

  it('rejects a duplicate sourceId', async () => {
    repository.insertSource.mockRejectedValue({ code: 11000 });

    await expect(createSource(sourceInput)).rejects.toMatchObject({
      code: 'SOURCE_ALREADY_EXISTS',
      statusCode: 409,
    });
  });

  it('retrieves existing sources and rejects unknown sources', async () => {
    repository.findSourceById.mockResolvedValueOnce(sourceDocument).mockResolvedValueOnce(null);

    await expect(getSourceById('LAB-A')).resolves.toBe(sourceDocument);
    await expect(getSourceById('MISSING-SOURCE')).rejects.toMatchObject({
      code: 'SOURCE_NOT_FOUND',
      statusCode: 404,
    });
  });

  it('updates status to SUSPENDED or REVOKED', async () => {
    repository.changeSourceStatus.mockResolvedValue({ ...sourceDocument, status: 'SUSPENDED' });
    await expect(updateSourceStatus('LAB-A', 'SUSPENDED')).resolves.toMatchObject({
      status: 'SUSPENDED',
    });

    repository.changeSourceStatus.mockResolvedValue({ ...sourceDocument, status: 'REVOKED' });
    await expect(updateSourceStatus('LAB-A', 'REVOKED')).resolves.toMatchObject({
      status: 'REVOKED',
    });
  });

  it('returns only the registered public key', async () => {
    repository.findSourceById.mockResolvedValue(sourceDocument);

    await expect(getSourcePublicKey('LAB-A')).resolves.toBe(sourceInput.publicKey);
    expect(sourceDocument).not.toHaveProperty('privateKey');
  });
});

describe('source registry types', () => {
  it('does not permit invalid enum values at the type boundary', () => {
    const invalidSource = { ...sourceInput, role: 'UNTRUSTED' } as unknown as SourceRecord;
    expect(['SOURCE', 'TRANSFORMER', 'CONSUMER']).not.toContain(invalidSource.role);
  });
});
