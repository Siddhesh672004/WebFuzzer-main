import { Queue } from 'bullmq';
import { getRedis } from './connection.js';
import { QUEUE_NAMES } from '@smartfuzz/shared/queues';

// Queue factory + registry. Backend imports buildQueue to enqueue; worker uses
// the same names to consume. Queues are cached so we don't open duplicate
// connections for the same name.

const cache = new Map();

// Sensible default job options: bounded retries with backoff, and automatic
// cleanup of completed/failed jobs so Redis doesn't grow unbounded.
const defaultJobOptions = {
  attempts: 3,
  backoff: { type: 'exponential', delay: 2000 },
  removeOnComplete: { age: 3600, count: 1000 },
  removeOnFail: { age: 86400, count: 5000 },
};

/** Get (or lazily create) a BullMQ Queue by name. */
export function buildQueue(name) {
  if (cache.has(name)) return cache.get(name);
  const queue = new Queue(name, {
    connection: getRedis(),
    defaultJobOptions,
  });
  cache.set(name, queue);
  return queue;
}

/** Eagerly build every known queue (used at startup for visibility). */
export function buildAllQueues() {
  return QUEUE_NAMES.map((name) => buildQueue(name));
}

/**
 * Enqueue a job by queue + job name. Thin wrapper over buildQueue().add so the
 * coordinator and module handlers don't each reach into BullMQ directly.
 * @param {string} queueName
 * @param {string} jobName
 * @param {object} data
 * @param {object} [opts]  BullMQ job options (e.g. { priority })
 */
export function enqueueJob(queueName, jobName, data, opts = {}) {
  return buildQueue(queueName).add(jobName, data, opts);
}

/** Enqueue many jobs onto one queue in a single round trip. */
export function enqueueBulk(queueName, jobs) {
  return buildQueue(queueName).addBulk(jobs);
}

/** Close all cached queues (shutdown + tests). */
export async function closeQueues() {
  await Promise.all([...cache.values()].map((q) => q.close()));
  cache.clear();
}

export { defaultJobOptions };
