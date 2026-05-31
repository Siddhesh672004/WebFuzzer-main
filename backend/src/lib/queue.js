import { Queue } from 'bullmq';
import { getRedis } from './redis.js';
import { QUEUES, JOBS, PRIORITY } from '@smartfuzz/shared/queues';

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

/**
 * Enqueue a verify-fix job: the worker re-fires the finding's exact payload and
 * updates its verificationStatus. Runs on the REPORT queue (the verify handler
 * dispatches by job name). `vuln` is passed inline so the worker needn't re-read
 * it, but vulnId is the source of truth for the status update.
 */
export function enqueueVerifyFix(scanId, vulnId, vuln) {
  return getQueue(QUEUES.REPORT).add(
    JOBS.VERIFY_FIX,
    { scanId: String(scanId), vulnId: String(vulnId), vuln },
    { priority: PRIORITY.MUTATION },
  );
}

export async function closeQueues() {
  await Promise.all([...cache.values()].map((q) => q.close()));
  cache.clear();
}
