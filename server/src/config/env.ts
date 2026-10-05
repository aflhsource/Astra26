import 'dotenv/config';
import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(4000),
  MONGODB_URI: z.string().min(1).default('mongodb://127.0.0.1:27017/trust_pass'),
  CORS_ORIGINS: z.string().default('http://localhost:5173'),
  BODY_LIMIT: z.string().default('1mb'),
  MAX_CLOCK_SKEW_MS: z.coerce.number().int().nonnegative().default(60000),
  MAX_MESSAGE_TTL_MS: z.coerce.number().int().positive().default(600000),
  TRUST_PASS_TTL_MS: z.coerce.number().int().positive().default(300000),
  GATEWAY_KEY_ID: z.string().min(1).default('trust-pass-gateway-key-1'),
  GATEWAY_PRIVATE_KEY_PATH: z.string().min(1).default('.demo-keys/gateway-private.pem'),
  GATEWAY_PUBLIC_KEY_PATH: z.string().min(1).default('.demo-keys/gateway-public.pem'),
  AI_PROVIDER: z.string().default('local'),
  AI_MODEL_VERSION: z.string().default('TP-LOCAL-RISK-1.0'),
});

export const env = envSchema.parse(process.env);

export const corsOrigins = env.CORS_ORIGINS.split(',')
  .map((origin) => origin.trim())
  .filter((origin) => origin.length > 0);
