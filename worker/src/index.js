import mongoose from 'mongoose';
import { config } from './config.js';
import { logger } from './logger.js';
import { getRedis, closeRedis } from './queue/connection.js';
import { registerWorker, closeWorkers } from './queue/workerFactory.js';
import { closeQueues } from './queue/queues.js';
import { QUEUES } from '@smartfuzz/shared/queues';
import { ScanRunner } from './scan/scanRunner.js';
import { publishProgress, closePublisher } from './scan/publisher.js';
import {
  makeCrawlHandler, makePassiveHandler, makeExposedHandler,
  makeTechHandler, makeAuthHandler, makeFuzzHandler,
} from './scan/modules.js';
import { buildVerifyHandler } from './scan/verifyHandler.js';

// Worker process bootstrap. Connects to Mongo + Redis and registers a worker
// per scanning-module queue.
//
// Two execution modes (WORKER_FANOUT):
//   • false (default) — the monolithic ScanRunner consumes ORCHESTRATE jobs and
//     runs every module in one process with one shared rate limiter. Proven,
//     simplest, the production default.
//   • true — true BullMQ fan-out: ORCHESTRATE seeds a CRAWL job, crawl fans out
//     one job per Phase-2 module (+ one fuzz job per endpoint), and a Redis
//     completion counter (coordinator.js) finalizes the scan when all finish.
//     Per-scan context (scanContext.js) preserves the single-rate-limiter
//     invariant across the fan-out jobs.

mongoose.set('strictQuery', true);

// Placeholder handler used when fan-out is disabled (these queues are dormant —
// ORCHESTRATE does all the work). Logs and no-ops.
function placeholder(moduleName) {
  return async (job) => {
    logger.warn(
      { module: moduleName, jobId: job.id, scanId: job.data?.scanId },
      `[${moduleName}] dormant (WORKER_FANOUT=false) — no-op`,
    );
    return { module: moduleName, status: 'dormant' };
  };
}

export async function start() {
  await mongoose.connect(config.MONGO_URI, { serverSelectionTimeoutMS: 5000 });
  logger.info('worker: MongoDB connected');

  const redis = getRedis(); // open the shared Redis connection

  if (config.WORKER_FANOUT) {
    // ── Real fan-out handlers ──
    const deps = { publish: publishProgress, redis };
    registerWorker(QUEUES.CRAWL, makeCrawlHandler(deps));
    registerWorker(QUEUES.PASSIVE, makePassiveHandler(deps));
    registerWorker(QUEUES.EXPOSED, makeExposedHandler(deps), { concurrency: 3 });
    registerWorker(QUEUES.TECH, makeTechHandler(deps));
    registerWorker(QUEUES.AUTH, makeAuthHandler(deps));
    registerWorker(QUEUES.FUZZ, makeFuzzHandler(deps), {
      concurrency: config.WORKER_FUZZ_CONCURRENCY,
    });

    // ORCHESTRATE seeds the fan-out by enqueuing the crawl job.
    registerWorker(QUEUES.ORCHESTRATE, async (job) => {
      const { scanId, targetUrl, config: scanCfg } = job.data;
      const { enqueueJob } = await import('./queue/queues.js');
      const { JOBS } = await import('@smartfuzz/shared/queues');
      await enqueueJob(QUEUES.CRAWL, JOBS.CRAWL_TARGET, { scanId, targetUrl, config: scanCfg || {} });
      return { scanId, mode: 'fanout', dispatched: 'crawl' };
    });

    logger.info('worker: fan-out mode — module workers registered');
  } else {
    // ── Monolithic mode (default): ORCHESTRATE runs the whole pipeline ──
    registerWorker(QUEUES.CRAWL, placeholder('crawler'));
    registerWorker(QUEUES.PASSIVE, placeholder('passiveAnalyzer'));
    registerWorker(QUEUES.EXPOSED, placeholder('exposedFiles'));
    registerWorker(QUEUES.FUZZ, placeholder('payloadFuzzer'), {
      concurrency: config.WORKER_FUZZ_CONCURRENCY,
    });
    registerWorker(QUEUES.AUTH, placeholder('authTester'));
    registerWorker(QUEUES.TECH, placeholder('techFingerprinter'));

    registerWorker(QUEUES.ORCHESTRATE, async (job) => {
      const { scanId, targetUrl, config: scanCfg } = job.data;
      const runner = new ScanRunner({
        scanId,
        targetUrl,
        publish: publishProgress,
        config: scanCfg || {},
      });
      return runner.run();
    });

    logger.info('worker: monolithic mode — orchestrator registered');
  }

  // Verify-fix worker (Phase 6): re-test a single finding's exact payload.
  registerWorker(QUEUES.REPORT, buildVerifyHandler({ publish: publishProgress }));

  logger.info('worker: all module workers registered');
}

export async function stop() {
  await closeWorkers();
  await closeQueues();
  await closePublisher();
  await closeRedis();
  if (mongoose.connection.readyState !== 0) await mongoose.disconnect();
  logger.info('worker: shutdown complete');
}

// Only auto-start when run directly (not when imported by tests).
const isMain = import.meta.url === `file://${process.argv[1]}` ||
  process.argv[1]?.endsWith('index.js');

if (isMain) {
  start().catch((err) => {
    logger.error({ err }, 'worker failed to start');
    process.exit(1);
  });

  const shutdown = async (signal) => {
    logger.info(`worker: ${signal} received`);
    await stop();
    process.exit(0);
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}
