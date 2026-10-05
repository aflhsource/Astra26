import { z } from 'zod';

const identifier = z.string().trim().min(1).max(200);
export const consumeSchema = z.object({
  body: z.object({
    transactionId: identifier,
    trustPassId: identifier,
    payload: z.unknown(),
    audience: identifier,
    purpose: identifier,
  }),
  params: z.object({}),
  query: z.object({}),
});
