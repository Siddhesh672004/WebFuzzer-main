import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import pinoHttp from 'pino-http';
import { config } from './config.js';
import { logger } from './logger.js';
import healthRoutes from './routes/health.routes.js';
import authRoutes from './routes/auth.routes.js';
import { notFoundHandler, errorHandler } from './middleware/error.middleware.js';

// App factory. Builds and returns the Express app WITHOUT calling listen(), so
// supertest can import it directly and tests never bind a port. server.js owns
// the lifecycle (DB connect, listen, graceful shutdown).

export function createApp() {
  const app = express();

  // Behind a reverse proxy in production (correct client IPs for rate limiting).
  app.set('trust proxy', 1);

  // SmartFuzz must pass its own scanner — security headers on by default.
  app.use(helmet());

  // Strict CORS: only our own frontend origin, credentials allowed (cookie JWT).
  app.use(
    cors({
      origin: config.FRONTEND_ORIGIN,
      credentials: true,
    }),
  );

  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: true, limit: '1mb' }));
  app.use(cookieParser());

  // Request logging (silent in tests via the logger config).
  app.use(
    pinoHttp({
      logger,
      autoLogging: { ignore: (req) => req.url === '/api/ping' || req.url === '/api/health' },
    }),
  );

  // Routes. All API surface is namespaced under /api.
  app.use('/api', healthRoutes);
  app.use('/api', authRoutes);

  // 404 + central error handler (must be last).
  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
