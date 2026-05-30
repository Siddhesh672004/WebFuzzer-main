import pino from 'pino';
import { config, isProd, isTest } from './config.js';

// Structured logger. Pretty-prints in dev for readability; JSON in prod for
// log aggregation. Silent during tests unless LOG_LEVEL is overridden.

const options = {
  level: isTest() ? 'silent' : config.LOG_LEVEL,
  base: { service: 'backend' },
  redact: {
    // Never log secrets or tokens, even if they appear on a logged object.
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      '*.password',
      '*.token',
      '*.otp',
      '*.jwt',
      'JWT_SECRET',
      'GMAIL_APP_PASSWORD',
    ],
    censor: '[redacted]',
  },
};

// pino-pretty transport only in dev (avoids the dep being required in prod).
const transport = !isProd() && !isTest()
  ? { target: 'pino-pretty', options: { colorize: true, translateTime: 'HH:MM:ss', ignore: 'pid,hostname,service' } }
  : undefined;

export const logger = pino(transport ? { ...options, transport } : options);

/** Create a child logger bound to a component name. */
export function childLogger(component, bindings = {}) {
  return logger.child({ component, ...bindings });
}
