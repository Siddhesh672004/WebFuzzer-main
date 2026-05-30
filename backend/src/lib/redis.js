import IORedis from 'ioredis';
import { config } from '../config.js';
import { childLogger } from '../logger.js';

// Backend Redis client — used for OTP storage (BullMQ has its own connection in
// the worker). A test seam (setRedisForTests) lets the auth suite inject an
// in-memory fake so tests need no live Redis. getRedis() is called lazily on
// each store operation, so the override always takes effect.

const log = childLogger('redis');

let client = null;
let override = null;

export function redisOptions() {
  const opts = {
    host: config.REDIS_HOST,
    port: config.REDIS_PORT,
    maxRetriesPerRequest: null,
    lazyConnect: false,
  };
  if (config.REDIS_PASSWORD) opts.password = config.REDIS_PASSWORD;
  return opts;
}

/** Lazily create the shared Redis client (or return the test override). */
export function getRedis() {
  if (override) return override;
  if (client) return client;
  client = new IORedis(redisOptions());
  client.on('connect', () => log.info('Redis connected'));
  client.on('error', (err) => log.error({ err }, 'Redis error'));
  return client;
}

/** Inject a fake client for tests. Pass null to clear. */
export function setRedisForTests(fake) {
  override = fake;
}

export async function closeRedis() {
  if (client) {
    await client.quit().catch(() => client.disconnect());
    client = null;
  }
}
