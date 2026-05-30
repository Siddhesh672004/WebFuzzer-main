import pino from 'pino';
import { config, isProd, isTest } from './config.js';

// Worker logger — mirrors the backend's setup but tagged service:worker so the
// two processes are distinguishable in aggregated logs.

const options = {
  level: isTest() ? 'silent' : config.LOG_LEVEL,
  base: { service: 'worker' },
  redact: {
    paths: ['*.password', '*.token', '*.cookie', 'REDIS_PASSWORD'],
    censor: '[redacted]',
  },
};

const transport = !isProd() && !isTest()
  ? { target: 'pino-pretty', options: { colorize: true, translateTime: 'HH:MM:ss', ignore: 'pid,hostname,service' } }
  : undefined;

export const logger = pino(transport ? { ...options, transport } : options);

export function childLogger(component, bindings = {}) {
  return logger.child({ component, ...bindings });
}
