import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { Payload } from '@smartfuzz/shared/models';
import { collectPayloads, seedPayloads } from '../seed.js';

// Seeding must be idempotent (Phase 1 requirement): re-running never duplicates.
// We test against in-memory Mongo using the real Payload model + its unique
// (type, value) index.

let mongod;

beforeAll(async () => {
  mongod = await MongoMemoryServer.create();
  await mongoose.connect(mongod.getUri());
  await Payload.init(); // build the unique index
});

afterEach(async () => {
  await Payload.deleteMany({});
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongod?.stop();
});

describe('collectPayloads', () => {
  it('returns the curated set when no wordlist repos are present', () => {
    // Point baseDir at a dir with no cloned repos → only curated payloads.
    const { records, dropped } = collectPayloads('/nonexistent-dir');
    expect(dropped).toBe(0);
    expect(records.length).toBeGreaterThan(40);
  });
});

describe('seedPayloads', () => {
  it('inserts payloads on first run', async () => {
    const { records } = collectPayloads('/nonexistent-dir');
    const result = await seedPayloads(records);
    expect(result.upserted).toBe(records.length);
    expect(result.total).toBe(records.length);
  });

  it('is idempotent — re-running does not duplicate', async () => {
    const { records } = collectPayloads('/nonexistent-dir');

    const first = await seedPayloads(records);
    const countAfterFirst = await Payload.estimatedDocumentCount();

    const second = await seedPayloads(records);
    const countAfterSecond = await Payload.estimatedDocumentCount();

    expect(countAfterSecond).toBe(countAfterFirst);
    expect(second.upserted).toBe(0); // nothing new inserted
    expect(first.upserted).toBe(records.length);
  });

  it('preserves successCount across re-seeds (only $setOnInsert sets it)', async () => {
    const records = [
      { type: 'sqli', value: "' OR 1=1 --", source: 'seclists', categories: [], tags: [], isActive: true },
    ];
    await seedPayloads(records);

    // Simulate a confirmed find bumping the counter.
    await Payload.updateOne({ type: 'sqli', value: "' OR 1=1 --" }, { $set: { successCount: 7 } });

    // Re-seed (e.g. tags changed upstream) must NOT reset successCount.
    await seedPayloads([{ ...records[0], tags: ['updated'] }]);

    const doc = await Payload.findOne({ type: 'sqli', value: "' OR 1=1 --" });
    expect(doc.successCount).toBe(7);
    expect(doc.tags).toEqual(['updated']); // $set fields still update
  });

  it('handles an empty record list', async () => {
    const result = await seedPayloads([]);
    expect(result.total).toBe(0);
    expect(result.upserted).toBe(0);
  });

  it('seeds the curated set with valid model documents', async () => {
    const { records } = collectPayloads('/nonexistent-dir');
    await seedPayloads(records);
    const sample = await Payload.findOne({ type: 'sqli' });
    expect(sample).toBeTruthy();
    expect(sample.isActive).toBe(true);
    expect(['seclists', 'payloadsallthethings', 'fuzzdb', 'nikto', 'custom']).toContain(sample.source);
  });
});
