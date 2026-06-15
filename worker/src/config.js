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

  // Screenshot evidence (Puppeteer). Off by default so the default build and
  // CI stay browser-free; opt in with SCAN_SCREENSHOTS=true. SCREENSHOT_DIR is
  // shared with the backend (Docker volume) so it can serve the captured PNGs.
  SCAN_SCREENSHOTS: boolish(false),
  SCREENSHOT_DIR: z.string().min(1).default('/tmp/smartfuzz-screenshots'),

  // Headless (browser) crawler — opt-in for SPA/JS-rendered targets. Uses the
  // Puppeteer/Chromium already present for screenshots (no extra dependency).
  // Off by default so the default build stays browser-free.
  SCAN_HEADLESS_CRAWLER: boolish(false),
  HEADLESS_MAX_PAGES: z.coerce.number().int().positive().default(20),
  HEADLESS_TIMEOUT_MS: z.coerce.number().int().positive().default(15000),

  // AI payload generation — off by default so CI/grading never needs a key or
  // network. 'gemini' uses the free Gemini API; 'ollama' uses a local model.
  AI_PAYLOAD_MODE: z.enum(['off', 'gemini', 'ollama']).default('off'),
  GEMINI_API_KEY: z.string().optional().default(''),
  GEMINI_MODEL: z.string().min(1).default('gemini-2.0-flash-lite'),
  OLLAMA_BASE_URL: z.string().min(1).default('http://localhost:11434'),
  OLLAMA_MODEL: z.string().min(1).default('mistral'),
  AI_PAYLOAD_RATE_LIMIT_COOLDOWN_MS: z.coerce.number().int().nonnegative().default(120000),
  AI_PAYLOAD_MAX_PER_TYPE: z.coerce.number().int().nonnegative().default(5),

  WORKER_FUZZ_CONCURRENCY: z.coerce.number().int().positive().default(5),

  // Fan-out mode: when true, a scan is split into one BullMQ job per module
  // (crawl → passive/exposed/tech/fuzz/auth) coordinated by a Redis counter,
  // instead of the single-process ScanRunner. The monolithic path remains the
  // default — it shares one rate limiter trivially and is the most battle-tested.
  WORKER_FANOUT: boolish(false),

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
