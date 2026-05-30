import IORedis from 'ioredis';
import { config } from '../config.js';
import { childLogger } from '../logger.js';

// Shared ioredis connection for BullMQ. BullMQ requires
// `maxRetriesPerRequest: null` on its connection or it throws at startup, so
// that's set here once and reused by every queue/worker factory.

const log = childLogger('redis');

let connection = null;

/** Build the ioredis connection options from config. */
export function redisOptions() {
  const opts = {
    host: config.REDIS_HOST,
    port: config.REDIS_PORT,
    maxRetriesPerRequest: null, // required by BullMQ
    enableReadyCheck: true,
  };
  if (config.REDIS_PASSWORD) opts.password = config.REDIS_PASSWORD;
  return opts;
}

/** Lazily create and cache the shared Redis connection. */
export function getRedis() {
  if (connection) return connection;
  connection = new IORedis(redisOptions());
  connection.on('connect', () => log.info('Redis connected'));
  connection.on('error', (err) => log.error({ err }, 'Redis error'));
  connection.on('close', () => log.warn('Redis connection closed'));
  return connection;
}

/** Close the shared connection (shutdown + tests). */
export async function closeRedis() {
  if (connection) {
    await connection.quit().catch(() => connection.disconnect());
    connection = null;
    log.info('Redis connection closed');
  }
}
