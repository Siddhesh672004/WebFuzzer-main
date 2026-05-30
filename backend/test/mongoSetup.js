import { MongoMemoryServer } from 'mongodb-memory-server';
import { connectMongo, disconnectMongo } from '../src/lib/db.js';
import { beforeAll, afterAll } from 'vitest';

// Process-level singleton so MongoMemoryServer is created exactly once across
// all test files (fileParallelism: false means one worker process).

beforeAll(async () => {
  if (!globalThis.__mongod) {
    globalThis.__mongod = await MongoMemoryServer.create();
    await connectMongo(globalThis.__mongod.getUri());
  }
}, 300000); // 5 min — first run downloads the MongoDB binary (~600MB)

afterAll(async () => {
  // Only tear down after the very last file — vitest calls afterAll per file,
  // so we guard with a counter.
  globalThis.__mongoFileCount = (globalThis.__mongoFileCount || 0) + 1;
  // We can't know the total file count here, so we skip teardown in setupFiles.
  // The process exits and cleans up automatically.
}, 10000);
