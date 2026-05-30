import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import {
  User,
  Target,
  Scan,
  Endpoint,
  Vulnerability,
  Payload,
  Report,
} from '../src/models/index.js';
import { signature } from '../src/signatures.js';

// Models are the shared data contract. These tests run against an in-memory
// Mongo and assert the constraints that protect data integrity: required
// fields, enums, and the unique indexes that prevent duplicates.

let mongod;

beforeAll(async () => {
  mongod = await MongoMemoryServer.create();
  await mongoose.connect(mongod.getUri());
  // Ensure indexes (incl. unique) are built before we test them.
  await Promise.all(
    [User, Target, Scan, Endpoint, Vulnerability, Payload, Report].map((m) => m.init()),
  );
});

afterEach(async () => {
  // Clean slate between tests.
  await Promise.all(
    Object.values(mongoose.connection.collections).map((c) => c.deleteMany({})),
  );
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongod?.stop();
});

describe('User model', () => {
  it('lowercases and trims email', async () => {
    const u = await User.create({ email: '  Test@Example.COM ' });
    expect(u.email).toBe('test@example.com');
    expect(u.totalScans).toBe(0);
  });

  it('rejects an invalid email', async () => {
    await expect(User.create({ email: 'not-an-email' })).rejects.toThrow();
  });

  it('enforces unique email', async () => {
    await User.create({ email: 'dup@example.com' });
    await expect(User.create({ email: 'dup@example.com' })).rejects.toThrow();
  });

  it('hides _id/__v and exposes id in JSON', async () => {
    const u = await User.create({ email: 'json@example.com' });
    const json = u.toJSON();
    expect(json.id).toBeDefined();
    expect(json._id).toBeUndefined();
    expect(json.__v).toBeUndefined();
  });
});

describe('Target model', () => {
  it('is unique per (userId, domain)', async () => {
    const userId = new mongoose.Types.ObjectId();
    await Target.create({ userId, origin: 'https://example.com', domain: 'example.com' });
    await expect(
      Target.create({ userId, origin: 'https://example.com', domain: 'example.com' }),
    ).rejects.toThrow();
  });

  it('allows the same domain for different users', async () => {
    const a = new mongoose.Types.ObjectId();
    const b = new mongoose.Types.ObjectId();
    await Target.create({ userId: a, origin: 'https://x.com', domain: 'x.com' });
    await expect(
      Target.create({ userId: b, origin: 'https://x.com', domain: 'x.com' }),
    ).resolves.toBeDefined();
  });
});

describe('Scan model', () => {
  const baseScan = () => ({
    userId: new mongoose.Types.ObjectId(),
    targetUrl: 'https://example.com',
    targetDomain: 'example.com',
    scanNumber: 1,
    consent: {
      authorized: true,
      confirmedAt: new Date(),
      userId: new mongoose.Types.ObjectId(),
      ip: '127.0.0.1',
    },
  });

  it('requires consent (audit/safety gate)', async () => {
    const noConsent = baseScan();
    delete noConsent.consent;
    await expect(Scan.create(noConsent)).rejects.toThrow();
  });

  it('applies config + progress + stats defaults', async () => {
    const s = await Scan.create(baseScan());
    expect(s.status).toBe('pending');
    expect(s.config.maxDepth).toBe(3);
    expect(s.config.modules).toContain('fuzzer');
    expect(s.stats.securityScore).toBe(100);
    expect(s.progress.percentComplete).toBe(0);
    // Per-module status map initialized to pending.
    expect(s.progress.moduleStatus.get('crawler')).toBe('pending');
  });

  it('rejects an invalid status', async () => {
    const bad = { ...baseScan(), status: 'exploding' };
    await expect(Scan.create(bad)).rejects.toThrow();
  });
});

describe('Endpoint model', () => {
  it('dedups on (scanId, url, method)', async () => {
    const scanId = new mongoose.Types.ObjectId();
    await Endpoint.create({ scanId, url: 'https://x.com/a', method: 'GET' });
    await expect(
      Endpoint.create({ scanId, url: 'https://x.com/a', method: 'GET' }),
    ).rejects.toThrow();
    // Different method is allowed.
    await expect(
      Endpoint.create({ scanId, url: 'https://x.com/a', method: 'POST' }),
    ).resolves.toBeDefined();
  });
});

describe('Vulnerability model', () => {
  const baseVuln = (over = {}) => ({
    scanId: new mongoose.Types.ObjectId(),
    signature: signature('sqli', '/login', 'user'),
    type: 'sqli',
    severity: 'critical',
    cvssScore: 10.0,
    ...over,
  });

  it('rejects an unregistered type', async () => {
    await expect(Vulnerability.create(baseVuln({ type: 'made_up' }))).rejects.toThrow();
  });

  it('rejects an invalid severity', async () => {
    await expect(Vulnerability.create(baseVuln({ severity: 'spicy' }))).rejects.toThrow();
  });

  it('rejects a cvssScore out of range', async () => {
    await expect(Vulnerability.create(baseVuln({ cvssScore: 11 }))).rejects.toThrow();
  });

  it('dedups on (scanId, signature)', async () => {
    const scanId = new mongoose.Types.ObjectId();
    const sig = signature('xss', '/search', 'q');
    await Vulnerability.create(baseVuln({ scanId, signature: sig, type: 'xss', severity: 'medium', cvssScore: 6.1 }));
    await expect(
      Vulnerability.create(baseVuln({ scanId, signature: sig, type: 'xss', severity: 'medium', cvssScore: 6.1 })),
    ).rejects.toThrow();
  });
});

describe('Payload model', () => {
  it('dedups on (type, value) for idempotent seeding', async () => {
    await Payload.create({ source: 'seclists', type: 'sqli', value: "' OR 1=1 --" });
    await expect(
      Payload.create({ source: 'seclists', type: 'sqli', value: "' OR 1=1 --" }),
    ).rejects.toThrow();
  });

  it('rejects an invalid source', async () => {
    await expect(
      Payload.create({ source: 'hackerone', type: 'sqli', value: 'x' }),
    ).rejects.toThrow();
  });
});

describe('Report model', () => {
  it('is unique per scanId', async () => {
    const scanId = new mongoose.Types.ObjectId();
    const base = {
      scanId,
      userId: new mongoose.Types.ObjectId(),
      targetUrl: 'https://x.com',
      targetDomain: 'x.com',
      scanNumber: 1,
    };
    await Report.create(base);
    await expect(Report.create(base)).rejects.toThrow();
  });
});
