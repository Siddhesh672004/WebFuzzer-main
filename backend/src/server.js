import { createApp } from './app.js';
import { config } from './config.js';
import { logger } from './logger.js';
import { connectMongo, disconnectMongo } from './lib/db.js';

// Server lifecycle: connect to Mongo, start listening, and shut down cleanly on
// SIGINT/SIGTERM. Kept separate from app.js so the app can be imported by tests
// without any of this running.

async function start() {
  await connectMongo(config.MONGO_URI);

  const app = createApp();
  const server = app.listen(config.PORT, () => {
    logger.info(`SmartFuzz backend listening on :${config.PORT} (${config.NODE_ENV})`);
  });

  const shutdown = async (signal) => {
    logger.info(`${signal} received — shutting down`);
    server.close(async () => {
      await disconnectMongo();
      logger.info('Shutdown complete');
      process.exit(0);
    });
    // Force-exit if connections don't drain in time.
    setTimeout(() => {
      logger.error('Forced shutdown after timeout');
      process.exit(1);
    }, 10000).unref();
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  process.on('unhandledRejection', (reason) => {
    logger.error({ reason }, 'Unhandled promise rejection');
  });
}

start().catch((err) => {
  logger.error({ err }, 'Failed to start backend');
  process.exit(1);
});
