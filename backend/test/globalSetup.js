import { MongoMemoryServer } from 'mongodb-memory-server';
import { connectMongo, disconnectMongo } from './src/lib/db.js';

// Global setup: one MongoMemoryServer shared across all test files so the
// mongoose singleton never has to reconnect between suites.

let mongod;

export async function setup() {
  mongod = await MongoMemoryServer.create();
  process.env.MONGO_TEST_URI = mongod.getUri();
  await connectMongo(mongod.getUri());
}

export async function teardown() {
  await disconnectMongo();
  await mongod?.stop();
}
