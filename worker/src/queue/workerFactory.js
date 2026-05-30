import { Worker } from 'bullmq';
import { getRedis } from './connection.js';
import { childLogger } from '../logger.js';

// Worker factory. Wraps a job handler with consistent logging and returns the
// BullMQ Worker so the bootstrap can track it for graceful shutdown. The
// handlers themselves live in src/workers/ and stay thin (pull job → call an
// engine module → write result → emit progress); all real logic is in engine/.

const registry = [];

/**
 * Register a BullMQ worker for a queue.
 * @param {string} queueName
 * @param {(job: import('bullmq').Job) => Promise<any>} handler
 * @param {object} [opts] BullMQ worker options (e.g. { concurrency })
 * @returns {import('bullmq').Worker}
 */
export function registerWorker(queueName, handler, opts = {}) {
  const log = childLogger('worker', { queue: queueName });

  const worker = new Worker(
    queueName,
    async (job) => {
      log.info({ jobId: job.id, name: job.name }, 'job started');
      const started = process.hrtime.bigint();
      try {
        const result = await handler(job);
        const ms = Number(process.hrtime.bigint() - started) / 1e6;
        log.info({ jobId: job.id, name: job.name, ms: Math.round(ms) }, 'job completed');
        return result;
      } catch (err) {
        log.error({ jobId: job.id, name: job.name, err }, 'job failed');
        throw err; // let BullMQ apply retry/backoff
      }
    },
    { connection: getRedis(), ...opts },
  );

  worker.on('error', (err) => log.error({ err }, 'worker error'));
  registry.push(worker);
  return worker;
}

/** All registered workers (for shutdown). */
export function registeredWorkers() {
  return registry.slice();
}

/** Close every registered worker. */
export async function closeWorkers() {
  await Promise.all(registry.map((w) => w.close()));
  registry.length = 0;
}
