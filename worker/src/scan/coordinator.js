import { Scan, Endpoint, Vulnerability } from '@smartfuzz/shared/models';
import { progressChannel, SSE_EVENTS } from '@smartfuzz/shared/progress';
import { QUEUES, JOBS, PRIORITY } from '@smartfuzz/shared/queues';
import { childLogger } from '../logger.js';

// Scan completion coordinator (Phase 3 fan-out). The orchestrator enqueues one
// job per Phase-2 module; each module decrements a Redis counter on completion.
// When the counter hits zero the scan is finalized and a report job is queued.
//
// The Redis client and the enqueue function are INJECTED so this module is unit
// testable without a live Redis/BullMQ (mirrors the engine's pure-deps style).
// Atomicity: we use a Lua DECR-and-read so the "decrement + test-for-zero" is a
// single round trip and two concurrent module completions can't both observe a
// non-zero count and skip finalization (or both observe zero and double-finish).

const log = childLogger('coordinator');

const COUNTER_TTL_SECONDS = 2 * 60 * 60; // 2h safety expiry

/** Redis key holding the count of outstanding Phase-2 jobs for a scan. */
export function pendingKey(scanId) {
  return `scan:pending:${scanId}`;
}

/** Redis key marking a scan as already finalized (idempotency guard). */
export function doneKey(scanId) {
  return `scan:done:${scanId}`;
}

/**
 * Initialize the outstanding-job counter for a scan.
 * @param {object} redis  ioredis-like client ({ set })
 * @param {string} scanId
 * @param {number} count  number of Phase-2 jobs being enqueued
 */
export async function initPending(redis, scanId, count) {
  await redis.set(pendingKey(scanId), String(count), 'EX', COUNTER_TTL_SECONDS);
}

/** Increment the counter (e.g. fuzzer fans out extra mutation jobs). */
export async function trackJobStart(redis, scanId, by = 1) {
  const n = await redis.incrby(pendingKey(scanId), by);
  await redis.expire(pendingKey(scanId), COUNTER_TTL_SECONDS).catch(() => {});
  return n;
}

// Atomic "decrement and return the new value" — single round trip.
const DECR_LUA = `
local v = redis.call('DECR', KEYS[1])
if v < 0 then redis.call('SET', KEYS[1], '0'); v = 0 end
return v
`;

/**
 * Decrement the counter for one finished module job. When it reaches zero,
 * finalize the scan exactly once.
 * @param {object} redis  ioredis-like client ({ eval, set, get })
 * @param {string} scanId
 * @param {object} [deps] { enqueue, models, publish }
 * @returns {Promise<{remaining:number, finalized:boolean}>}
 */
export async function trackJobDone(redis, scanId, deps = {}) {
  let remaining;
  try {
    remaining = await redis.eval(DECR_LUA, 1, pendingKey(scanId));
  } catch (err) {
    // Fallback for clients without eval (some mocks): non-atomic DECR.
    log.warn({ err: err.message, scanId }, 'eval unavailable, using DECR fallback');
    remaining = await redis.decr(pendingKey(scanId));
    if (remaining < 0) {
      await redis.set(pendingKey(scanId), '0');
      remaining = 0;
    }
  }
  remaining = Number(remaining);

  if (remaining <= 0) {
    const finalized = await completeScan(redis, scanId, deps);
    return { remaining: 0, finalized };
  }
  return { remaining, finalized: false };
}

/**
 * Finalize a scan: compute stats from persisted vulns, mark completed, enqueue
 * the report job, and publish the 'done' SSE event. Idempotent via doneKey.
 * @returns {Promise<boolean>} true if this call performed finalization
 */
export async function completeScan(redis, scanId, deps = {}) {
  const models = deps.models || { Scan, Vulnerability, Endpoint };
  const publish = deps.publish || (() => {});
  const enqueue = deps.enqueue;

  // Idempotency: SET NX so only the first finalizer proceeds. Real ioredis
  // returns 'OK' when the key was set and null when it already existed.
  const won = await redis.set(doneKey(scanId), '1', 'EX', COUNTER_TTL_SECONDS, 'NX').catch(() => 'OK');
  if (won === null) {
    log.info({ scanId }, 'scan already finalized — skipping');
    return false;
  }

  // Aggregate severity counts from persisted findings.
  const counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  let totalVulns = 0;
  let totalEndpoints = 0;
  try {
    const vulns = await models.Vulnerability.find({ scanId }).select('severity').lean();
    totalVulns = vulns.length;
    for (const v of vulns) counts[v.severity] = (counts[v.severity] || 0) + 1;
    totalEndpoints = await models.Endpoint.countDocuments({ scanId });
  } catch (err) {
    log.warn({ err: err.message, scanId }, 'failed to aggregate scan stats');
  }

  const securityScore = Math.max(
    0,
    100 - counts.critical * 20 - counts.high * 10 - counts.medium * 5 - counts.low * 2,
  );

  try {
    await models.Scan.updateOne(
      { _id: scanId },
      {
        $set: {
          status: 'completed',
          'progress.percentComplete': 100,
          'stats.endTime': new Date(),
          'stats.totalEndpoints': totalEndpoints,
          'stats.totalVulnerabilities': totalVulns,
          'stats.critical': counts.critical,
          'stats.high': counts.high,
          'stats.medium': counts.medium,
          'stats.low': counts.low,
          'stats.informational': counts.informational,
          'stats.securityScore': securityScore,
        },
      },
    );
  } catch (err) {
    log.warn({ err: err.message, scanId }, 'failed to mark scan completed');
  }

  // Enqueue the report build (best-effort; report is regenerated on demand too).
  if (enqueue) {
    try {
      await enqueue(QUEUES.REPORT, JOBS.GENERATE_REPORT, { scanId }, { priority: PRIORITY.LOW });
    } catch (err) {
      log.warn({ err: err.message, scanId }, 'failed to enqueue report job');
    }
  }

  publish(scanId, { kind: SSE_EVENTS.STATUS, data: { status: 'completed' } });
  publish(scanId, {
    kind: SSE_EVENTS.DONE,
    data: { status: 'completed', securityScore, totalVulnerabilities: totalVulns, counts },
  });

  // Best-effort counter cleanup.
  await redis.del(pendingKey(scanId)).catch(() => {});

  log.info({ scanId, totalVulns, securityScore }, 'scan finalized');
  return true;
}
