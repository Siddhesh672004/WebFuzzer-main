import mongoose from 'mongoose';
import { config } from './config.js';
import { logger } from './logger.js';
import { getRedis, closeRedis } from './queue/connection.js';
import { registerWorker, closeWorkers } from './queue/workerFactory.js';
import { closeQueues } from './queue/queues.js';
import { QUEUES } from '@smartfuzz/shared/queues';

// Worker process bootstrap. Connects to Mongo + Redis and registers a worker
// per scanning-module queue. Handlers are placeholders for now — Phase 2+
// swaps each one for a thin wrapper that calls the corresponding engine module.
// Keeping the bootstrap stable means later phases only touch src/workers/.

mongoose.set('strictQuery', true);

// Placeholder handler used until a module is implemented. Logs and no-ops so
// the pipeline wiring is verifiable end-to-end before the engine exists.
function placeholder(moduleName) {
  return async (job) => {
    logger.warn(
      { module: moduleName, jobId: job.id, scanId: job.data?.scanId },
      `[${moduleName}] not yet implemented — no-op`,
    );
    return { module: moduleName, status: 'not_implemented' };
  };
}

export async function start() {
  await mongoose.connect(config.MONGO_URI, { serverSelectionTimeoutMS: 5000 });
  logger.info('worker: MongoDB connected');

  getRedis(); // open the shared Redis connection

  // One worker per module queue. fuzz gets the configured concurrency; the
  // rest default to 1 (they're coarse-grained, one job per scan).
  registerWorker(QUEUES.CRAWL, placeholder('crawler'));
  registerWorker(QUEUES.PASSIVE, placeholder('passiveAnalyzer'));
  registerWorker(QUEUES.EXPOSED, placeholder('exposedFiles'));
  registerWorker(QUEUES.FUZZ, placeholder('payloadFuzzer'), {
    concurrency: config.WORKER_FUZZ_CONCURRENCY,
  });
  registerWorker(QUEUES.AUTH, placeholder('authTester'));
  registerWorker(QUEUES.TECH, placeholder('techFingerprinter'));
  registerWorker(QUEUES.ORCHESTRATE, placeholder('orchestrator'));
  registerWorker(QUEUES.REPORT, placeholder('reportGenerator'));

  logger.info('worker: all module workers registered');
}

export async function stop() {
  await closeWorkers();
  await closeQueues();
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
