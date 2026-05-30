import mongoose from 'mongoose';
import { childLogger } from '../logger.js';

const log = childLogger('mongo');

// Thin wrapper around mongoose.connect with sensible defaults and logging.
// Tests use mongodb-memory-server and call connectMongo with its URI, so this
// stays environment-agnostic.

mongoose.set('strictQuery', true);

let connecting = null;

/**
 * Connect to MongoDB (idempotent — returns the existing connection if already
 * connected/connecting).
 * @param {string} uri
 */
export async function connectMongo(uri) {
  if (mongoose.connection.readyState === 1) return mongoose.connection;
  if (connecting) return connecting;

  connecting = mongoose
    .connect(uri, {
      serverSelectionTimeoutMS: 5000,
      maxPoolSize: 10,
    })
    .then((m) => {
      log.info('MongoDB connected');
      return m.connection;
    })
    .catch((err) => {
      connecting = null;
      log.error({ err }, 'MongoDB connection failed');
      throw err;
    });

  mongoose.connection.on('disconnected', () => log.warn('MongoDB disconnected'));
  mongoose.connection.on('reconnected', () => log.info('MongoDB reconnected'));

  return connecting;
}

/** Gracefully close the connection (used on shutdown and in tests). */
export async function disconnectMongo() {
  connecting = null;
  if (mongoose.connection.readyState !== 0) {
    await mongoose.disconnect();
    log.info('MongoDB connection closed');
  }
}
