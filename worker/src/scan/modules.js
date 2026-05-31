import { QUEUES, JOBS, PRIORITY } from '@smartfuzz/shared/queues';
import { SSE_EVENTS } from '@smartfuzz/shared/progress';
import { crawl } from '../engine/crawler.js';
import { analyzePassive } from '../engine/passiveAnalyzer.js';
import { scanExposedFiles } from '../engine/exposedFiles.js';
import { fingerprint } from '../engine/techFingerprinter.js';
import { fuzzEndpoint } from '../engine/payloadFuzzer.js';
import { mutate } from '../engine/mutationEngine.js';
import { testAuth } from '../engine/authTester.js';
import { getScanContext, releaseScanContext } from './scanContext.js';
import { initPending, trackJobDone } from './coordinator.js';
import { enqueueJob, enqueueBulk } from '../queue/queues.js';
import { childLogger } from '../logger.js';

// Fan-out module handlers (Phase 3). Each is a thin BullMQ job handler that:
//   1. resolves the shared per-scan context (one rate limiter / HttpClient),
//   2. runs its engine module,
//   3. persists findings via the context,
//   4. (for Phase-2 modules) decrements the completion counter.
//
// The CRAWL handler is special: it runs first, persists endpoints, then fans
// out the Phase-2 jobs and seeds the counter. Every outbound request still goes
// through HttpClient → assertSafeUrl, so the SSRF defense is intact.

const log = childLogger('modules');

/** Build the context-construction opts carried on every fan-out job. */
function ctxOptsFromJob(job, publish) {
  const { scanId, targetUrl, config = {} } = job.data;
  return { scanId, targetUrl, config, publish };
}

// ── CRAWL: runs first, then fans out Phase 2 ──
export function makeCrawlHandler({ publish, redis }) {
  return async (job) => {
    const { scanId, targetUrl, config = {} } = job.data;
    const ctx = getScanContext(ctxOptsFromJob(job, publish));

    await ctx.models.Scan.updateOne(
      { _id: scanId },
      { $set: { status: 'running', 'stats.startTime': new Date() } },
    ).catch(() => {});
    ctx.emit(SSE_EVENTS.STATUS, { status: 'running' });
    ctx.setModule('crawler', 'running');

    let endpoints = [];
    try {
      const result = await crawl(targetUrl, ctx.http, {
        maxDepth: config.maxDepth ?? 3,
        maxEndpoints: config.maxEndpoints ?? 500,
      });
      endpoints = result.endpoints || [];
      for (const e of endpoints) {
        // eslint-disable-next-line no-await-in-loop
        await ctx.models.Endpoint.updateOne(
          { scanId, url: e.url, method: e.method },
          { $setOnInsert: { ...e, scanId } },
          { upsert: true },
        ).catch(() => {});
      }
      ctx.endpointCount = endpoints.length;
    } catch (err) {
      log.error({ err: err.message, scanId }, 'crawl failed');
    }
    ctx.setModule('crawler', 'completed', `${endpoints.length} endpoints`);

    // Fan out Phase 2: passive, exposed, tech, auth (one each) + one fuzz job
    // per endpoint. Seed the counter with the exact number of jobs first so a
    // fast-finishing module can't drive it to zero before all are enqueued.
    const fuzzable = endpoints.filter((e) => (e.params || []).length > 0);
    const phase2Count = 4 + fuzzable.length; // passive+exposed+tech+auth + fuzz jobs
    await initPending(redis, scanId, phase2Count);

    const base = { scanId, targetUrl, config };
    await Promise.all([
      enqueueJob(QUEUES.PASSIVE, JOBS.PASSIVE_ANALYZE, base, { priority: PRIORITY.NORMAL }),
      enqueueJob(QUEUES.EXPOSED, JOBS.SCAN_EXPOSED, base, { priority: PRIORITY.NORMAL }),
      enqueueJob(QUEUES.TECH, JOBS.TECH_FINGERPRINT, base, { priority: PRIORITY.NORMAL }),
      enqueueJob(QUEUES.AUTH, JOBS.AUTH_TEST, base, { priority: PRIORITY.NORMAL }),
    ]);

    if (fuzzable.length > 0) {
      await enqueueBulk(
        QUEUES.FUZZ,
        fuzzable.map((e) => ({
          name: JOBS.FUZZ_ENDPOINT,
          data: { ...base, endpoint: { url: e.url, method: e.method, params: e.params } },
          opts: { priority: PRIORITY.NORMAL },
        })),
      );
    }

    return { module: 'crawler', endpoints: endpoints.length, phase2Jobs: phase2Count };
  };
}

// ── Generic Phase-2 wrapper: run module fn, save findings, decrement counter ──
function makePhase2Handler({ publish, redis, name, run }) {
  return async (job) => {
    const { scanId } = job.data;
    const ctx = getScanContext(ctxOptsFromJob(job, publish));
    ctx.setModule(name, 'running');
    try {
      await run(ctx, job);
      ctx.setModule(name, 'completed');
    } catch (err) {
      log.warn({ err: err.message, scanId, module: name }, 'module failed');
      ctx.setModule(name, 'failed');
    }
    const { finalized } = await trackJobDone(redis, scanId, {
      publish,
      models: ctx.models,
      enqueue: enqueueJob,
    });
    if (finalized) releaseScanContext(scanId);
    return { module: name };
  };
}

export function makePassiveHandler(deps) {
  return makePhase2Handler({
    ...deps, name: 'passive',
    run: async (ctx) => {
      const res = await ctx.http.get(ctx.targetUrl);
      if (res.ok) {
        const findings = analyzePassive({
          url: res.finalUrl || ctx.targetUrl, status: res.status,
          headers: res.headers, body: res.body, responseTimeMs: res.timeMs,
        });
        await ctx.saveFindings(findings);
      }
    },
  });
}

export function makeExposedHandler(deps) {
  return makePhase2Handler({
    ...deps, name: 'exposed',
    run: async (ctx) => {
      const { findings } = await scanExposedFiles(ctx.targetUrl, ctx.http, {});
      await ctx.saveFindings(findings);
    },
  });
}

export function makeTechHandler(deps) {
  return makePhase2Handler({
    ...deps, name: 'tech',
    run: async (ctx) => {
      const res = await ctx.http.get(ctx.targetUrl);
      if (res.ok) {
        const { findings } = fingerprint({ url: res.finalUrl || ctx.targetUrl, headers: res.headers, body: res.body });
        await ctx.saveFindings(findings);
      }
    },
  });
}

export function makeAuthHandler(deps) {
  return makePhase2Handler({
    ...deps, name: 'auth',
    run: async (ctx) => {
      const { findings } = await testAuth(ctx.targetUrl, ctx.http);
      await ctx.saveFindings(findings);
    },
  });
}

// ── FUZZ: one endpoint per job; HIGH_INTEREST fans out mutation jobs ──
export function makeFuzzHandler({ publish, redis }) {
  return async (job) => {
    const { scanId, endpoint } = job.data;
    const ctx = getScanContext(ctxOptsFromJob(job, publish));
    ctx.setModule('fuzzer', 'running');
    try {
      const { findings } = await fuzzEndpoint(endpoint, ctx.http, {
        maxPayloads: 50,
        onFinding: (f) => ctx.saveFindings([f]),
      });
      await ctx.saveFindings(findings);
    } catch (err) {
      log.warn({ err: err.message, scanId, url: endpoint?.url }, 'fuzz endpoint failed');
    }
    const { finalized } = await trackJobDone(redis, scanId, {
      publish, models: ctx.models, enqueue: enqueueJob,
    });
    if (finalized) releaseScanContext(scanId);
    return { module: 'fuzzer', url: endpoint?.url };
  };
}
