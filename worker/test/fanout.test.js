import { describe, it, expect, beforeEach } from 'vitest';
import { initPending, trackJobStart, trackJobDone, completeScan, pendingKey, doneKey } from '../src/scan/coordinator.js';

// Phase 9 — scan completion coordinator. Uses an in-memory Redis fake that
// implements the exact subset the coordinator calls (set/get/incrby/decr/eval/
// del/expire), including SET NX semantics. No live Redis or BullMQ needed.

class FakeRedis {
  constructor() { this.store = new Map(); }
  async set(key, value, ...rest) {
    const nx = rest.includes('NX');
    if (nx && this.store.has(key)) return null; // NX: key exists → no-op
    this.store.set(key, String(value));
    return 'OK';
  }
  async get(key) { return this.store.has(key) ? this.store.get(key) : null; }
  async incrby(key, by) { const n = (Number(this.store.get(key)) || 0) + by; this.store.set(key, String(n)); return n; }
  async decr(key) { const n = (Number(this.store.get(key)) || 0) - 1; this.store.set(key, String(n)); return n; }
  async expire() { return 1; }
  async del(key) { this.store.delete(key); return 1; }
  // Lua DECR-and-clamp used by trackJobDone.
  async eval(_lua, _numKeys, key) {
    let v = (Number(this.store.get(key)) || 0) - 1;
    if (v < 0) { v = 0; this.store.set(key, '0'); } else { this.store.set(key, String(v)); }
    return v;
  }
}

// Mongo-ish model stubs so completeScan can aggregate + persist without a DB.
function fakeDeps(vulns = [{ severity: 'critical' }, { severity: 'high' }]) {
  const enqueued = [];
  const scanUpdates = [];
  const published = [];
  return {
    enqueued, scanUpdates, published,
    deps: {
      publish: (scanId, event) => published.push({ scanId, event }),
      enqueue: async (queue, job, data, opts) => { enqueued.push({ queue, job, data, opts }); },
      models: {
        Vulnerability: { find: () => ({ select: () => ({ lean: async () => vulns }) }) },
        Endpoint: { countDocuments: async () => 7 },
        Scan: { updateOne: async (q, u) => { scanUpdates.push(u); return {}; } },
      },
    },
  };
}

let redis;
beforeEach(() => { redis = new FakeRedis(); });

describe('coordinator — counter lifecycle', () => {
  it('initializes and reads the pending counter', async () => {
    await initPending(redis, 's1', 6);
    expect(await redis.get(pendingKey('s1'))).toBe('6');
  });

  it('trackJobStart increments (mutation fan-out)', async () => {
    await initPending(redis, 's1', 6);
    const n = await trackJobStart(redis, 's1', 3);
    expect(n).toBe(9);
  });

  it('decrements without finalizing until zero', async () => {
    const { deps } = fakeDeps();
    await initPending(redis, 's1', 3);
    const a = await trackJobDone(redis, 's1', deps);
    const b = await trackJobDone(redis, 's1', deps);
    expect(a).toEqual({ remaining: 2, finalized: false });
    expect(b).toEqual({ remaining: 1, finalized: false });
  });

  it('finalizes exactly once when the counter reaches zero', async () => {
    const { deps, enqueued, published } = fakeDeps();
    await initPending(redis, 's1', 2);
    await trackJobDone(redis, 's1', deps);
    const last = await trackJobDone(redis, 's1', deps);
    expect(last.finalized).toBe(true);
    // Report job enqueued once.
    expect(enqueued.filter((e) => e.job === 'generate-report')).toHaveLength(1);
    // 'done' SSE event published.
    expect(published.some((p) => p.event.kind === 'done')).toBe(true);
  });

  it('does not double-finalize on a late extra completion', async () => {
    const { deps, enqueued } = fakeDeps();
    await initPending(redis, 's1', 1);
    const first = await trackJobDone(redis, 's1', deps); // → 0, finalizes
    const late = await trackJobDone(redis, 's1', deps);  // late mutation job
    expect(first.finalized).toBe(true);
    expect(late.finalized).toBe(false);
    expect(enqueued.filter((e) => e.job === 'generate-report')).toHaveLength(1);
  });
});

describe('coordinator — completeScan', () => {
  it('computes the security score from persisted findings', async () => {
    const { deps, scanUpdates } = fakeDeps([{ severity: 'critical' }, { severity: 'high' }]);
    await completeScan(redis, 's2', deps);
    const set = scanUpdates[0].$set;
    expect(set.status).toBe('completed');
    expect(set['stats.totalVulnerabilities']).toBe(2);
    expect(set['stats.critical']).toBe(1);
    expect(set['stats.high']).toBe(1);
    // 100 - 20 (critical) - 10 (high) = 70
    expect(set['stats.securityScore']).toBe(70);
  });

  it('marks the done key so a second finalize is a no-op', async () => {
    const { deps } = fakeDeps();
    const first = await completeScan(redis, 's3', deps);
    const second = await completeScan(redis, 's3', deps);
    expect(first).toBe(true);
    expect(second).toBe(false);
    expect(await redis.get(doneKey('s3'))).toBe('1');
  });
});
