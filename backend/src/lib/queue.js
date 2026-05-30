import { Queue } from 'bullmq';
import { getRedis } from './redis.js';
import { QUEUES } from '@smartfuzz/shared/queues';

// Backend-side queue access — the API ENQUEUES scan jobs; the worker consumes
// them. Reuses the backend Redis client (BullMQ needs maxRetriesPerRequest:null,
// which redis.js sets). Queues are cached so we don't reopen connections.

const cache = new Map();

const defaultJobOptions = {
  attempts: 2,
  backoff: { type: 'exponential', delay: 2000 },
  removeOnComplete: { age: 3600, count: 500 },
  removeOnFail: { age: 86400, count: 1000 },
};

export function getQueue(name) {
  if (cache.has(name)) return cache.get(name);
  const q = new Queue(name, { connection: getRedis(), defaultJobOptions });
  cache.set(name, q);
  return q;
}

/** Enqueue the orchestration job that kicks off a scan in the worker. */
export function enqueueScan(scanId, targetUrl, config) {
  return getQueue(QUEUES.ORCHESTRATE).add('start-scan', { scanId: String(scanId), targetUrl, config });
}

export async function closeQueues() {
  await Promise.all([...cache.values()].map((q) => q.close()));
  cache.clear();
}
