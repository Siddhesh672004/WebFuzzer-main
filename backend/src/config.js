import { z } from 'zod';

// Validate and freeze all environment configuration at startup. A bad/missing
// value fails fast with a clear message rather than surfacing as a confusing
// runtime error later. Imported by both backend and (a subset by) the worker.

// Coerce common string booleans → boolean.
const boolish = (def) =>
  z
    .union([z.boolean(), z.string()])
    .transform((v) => (typeof v === 'boolean' ? v : ['1', 'true', 'yes', 'on'].includes(v.toLowerCase())))
    .default(def);

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(4000),
  FRONTEND_ORIGIN: z.string().url().default('http://localhost:5173'),

  MONGO_URI: z.string().min(1).default('mongodb://localhost:27017/smartfuzz'),
  REDIS_HOST: z.string().min(1).default('localhost'),
  REDIS_PORT: z.coerce.number().int().positive().default(6379),
  REDIS_PASSWORD: z.string().optional().default(''),

  JWT_SECRET: z.string().min(8).default('dev-insecure-secret-change-me'),
  JWT_EXPIRES_IN: z.string().default('7d'),
  AUTH_COOKIE_NAME: z.string().default('smartfuzz_token'),

  OTP_TTL_SECONDS: z.coerce.number().int().positive().default(600),
  OTP_MAX_ATTEMPTS: z.coerce.number().int().positive().default(3),
  OTP_RESEND_COOLDOWN_SECONDS: z.coerce.number().int().nonnegative().default(60),

  MAIL_TRANSPORT: z.enum(['ethereal', 'gmail', 'json']).default('ethereal'),
  MAIL_FROM: z.string().default('SmartFuzz <no-reply@smartfuzz.local>'),
  GMAIL_USER: z.string().optional().default(''),
  GMAIL_APP_PASSWORD: z.string().optional().default(''),

  SCAN_RATE_LIMIT: z.coerce.number().positive().default(10),
  SCAN_MAX_DEPTH: z.coerce.number().int().nonnegative().default(3),
  SCAN_MAX_ENDPOINTS: z.coerce.number().int().positive().default(500),
  SCAN_REQUEST_TIMEOUT_MS: z.coerce.number().int().positive().default(10000),
  SCAN_WALLCLOCK_BUDGET_MS: z.coerce.number().int().positive().default(1800000),
  SCAN_MAX_BODY_BYTES: z.coerce.number().int().positive().default(2097152),
  SCAN_ALLOW_PRIVATE: boolish(false),

  // Directory where the worker writes screenshot evidence PNGs. Shared with the
  // worker via a Docker volume so the backend can serve them over /api/screenshots.
  SCREENSHOT_DIR: z.string().min(1).default('/tmp/smartfuzz-screenshots'),

  WORKER_FUZZ_CONCURRENCY: z.coerce.number().int().positive().default(5),

  // Demo mode — pre-fills the New Scan page with an authorized public test
  // target and shows a banner. Surfaced to the frontend via GET /api/meta.
  SMARTFUZZ_DEMO_MODE: boolish(false),
  SMARTFUZZ_DEMO_TARGET: z.string().default('http://testphp.vulnweb.com'),

  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
});

/**
 * Parse an env-like object into validated config. Exported for testability so
 * tests can pass a controlled object instead of mutating process.env.
 * @param {Record<string,string|undefined>} env
 */
export function loadConfig(env = process.env) {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    throw new Error(`Invalid environment configuration:\n${issues}`);
  }
  return Object.freeze(parsed.data);
}

// Eagerly-loaded singleton for app code. Tests import loadConfig directly.
export const config = loadConfig();

export const isProd = () => config.NODE_ENV === 'production';
export const isTest = () => config.NODE_ENV === 'test';
export const isDev = () => config.NODE_ENV === 'development';
