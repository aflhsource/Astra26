import { z } from 'zod';
import { sourceRoles, sourceStatuses, sourceTypes } from './source.types.js';

const sourceId = z
  .string()
  .trim()
  .min(1)
  .max(100)
  .regex(/^[A-Za-z0-9_-]+$/);
const nonEmptyText = z.string().trim().min(1).max(200);

export const listSourcesSchema = z.object({
  body: z.unknown().optional(),
  params: z.object({}),
  query: z.object({}),
});

export const sourceIdSchema = z.object({
  body: z.unknown().optional(),
  params: z.object({ sourceId }),
  query: z.object({}),
});

export const createSourceSchema = z.object({
  body: z.object({
    sourceId,
    name: nonEmptyText,
    role: z.enum(sourceRoles),
    type: z.enum(sourceTypes),
    status: z.enum(sourceStatuses),
    keyId: nonEmptyText,
    publicKey: z.string().trim().min(1),
    allowedTransformations: z.array(nonEmptyText).max(50).default([]),
  }),
  params: z.object({}),
  query: z.object({}),
});

export const updateSourceStatusSchema = z.object({
  body: z.object({ status: z.enum(sourceStatuses) }),
  params: z.object({ sourceId }),
  query: z.object({}),
});

export type CreateSourceRequest = z.infer<typeof createSourceSchema>['body'];
