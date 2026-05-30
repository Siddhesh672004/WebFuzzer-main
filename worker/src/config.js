import { z } from 'zod';

// Worker config — the subset of environment the scan engine needs. Kept
// separate from the backend config so the worker process doesn't pull in
// backend-only concerns (JWT, mail, CORS). Same fail-fast philosophy.

const boolish = (def) =>
  z
    .union([z.boolean(), z.string()])
    .transform((v) => (typeof v === 'boolean' ? v : ['1', 'true', 'yes', 'on'].includes(v.toLowerCase())))
    .default(def);

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),

  MONGO_URI: z.string().min(1).default('mongodb://localhost:27017/smartfuzz'),
  REDIS_HOST: z.string().min(1).default('localhost'),
  REDIS_PORT: z.coerce.number().int().positive().default(6379),
  REDIS_PASSWORD: z.string().optional().default(''),

  // Outbound scan safety
  SCAN_RATE_LIMIT: z.coerce.number().positive().default(10),
  SCAN_MAX_DEPTH: z.coerce.number().int().nonnegative().default(3),
  SCAN_MAX_ENDPOINTS: z.coerce.number().int().positive().default(500),
  SCAN_REQUEST_TIMEOUT_MS: z.coerce.number().int().positive().default(10000),
  SCAN_WALLCLOCK_BUDGET_MS: z.coerce.number().int().positive().default(1800000),
  SCAN_MAX_BODY_BYTES: z.coerce.number().int().positive().default(2097152),
  SCAN_ALLOW_PRIVATE: boolish(false),

  WORKER_FUZZ_CONCURRENCY: z.coerce.number().int().positive().default(5),

  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
});

export function loadConfig(env = process.env) {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    throw new Error(`Invalid worker environment configuration:\n${issues}`);
  }
  return Object.freeze(parsed.data);
}

export const config = loadConfig();
export const isTest = () => config.NODE_ENV === 'test';
export const isProd = () => config.NODE_ENV === 'production';
