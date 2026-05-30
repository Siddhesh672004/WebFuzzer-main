import { childLogger } from '../logger.js';
import { isProd } from '../config.js';

const log = childLogger('http');

/**
 * AppError — throw this (or subclasses) from controllers/services to produce a
 * controlled HTTP response. Anything else that reaches the error handler is
 * treated as an unexpected 500.
 */
export class AppError extends Error {
  constructor(statusCode, message, { code = undefined, details = undefined } = {}) {
    super(message);
    this.name = 'AppError';
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.expose = true; // safe to show this message to the client
  }
}

export const badRequest = (msg, opts) => new AppError(400, msg, opts);
export const unauthorized = (msg = 'Unauthorized', opts) => new AppError(401, msg, opts);
export const forbidden = (msg = 'Forbidden', opts) => new AppError(403, msg, opts);
export const notFound = (msg = 'Not found', opts) => new AppError(404, msg, opts);
export const tooManyRequests = (msg = 'Too many requests', opts) => new AppError(429, msg, opts);

/** 404 handler for unmatched routes. */
export function notFoundHandler(req, res, next) {
  next(new AppError(404, `Route not found: ${req.method} ${req.path}`, { code: 'ROUTE_NOT_FOUND' }));
}

/**
 * Central error handler. Maps known error shapes to clean JSON; hides internal
 * details for unexpected errors in production. Must be registered last.
 */
// eslint-disable-next-line no-unused-vars -- Express needs the 4-arg signature
export function errorHandler(err, req, res, next) {
  // Zod validation errors → 400 with field details.
  if (err?.name === 'ZodError') {
    return res.status(400).json({
      error: 'Validation failed',
      code: 'VALIDATION_ERROR',
      details: err.issues?.map((i) => ({ path: i.path.join('.'), message: i.message })),
    });
  }

  const statusCode = err.statusCode ?? 500;

  if (statusCode >= 500) {
    log.error({ err, path: req.path, method: req.method }, 'Unhandled error');
  } else {
    log.warn({ msg: err.message, path: req.path, code: err.code }, 'Request error');
  }

  const body = { error: undefined, code: err.code };
  if (err.expose && statusCode < 500) {
    body.error = err.message;
    if (err.details) body.details = err.details;
  } else {
    body.error = isProd() ? 'Internal server error' : err.message;
    if (!isProd() && err.stack) body.stack = err.stack;
  }

  res.status(statusCode).json(body);
}

/** Wrap an async route handler so thrown/rejected errors reach errorHandler. */
export function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}
