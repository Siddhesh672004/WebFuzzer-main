import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';

vi.mock('../src/lib/queue.js', () => ({
  enqueueScan: vi.fn(() => Promise.resolve({ id: 'job1' })),
  getQueue: vi.fn(),
  closeQueues: vi.fn(),
}));

import { createApp } from '../src/app.js';
import { setRedisForTests } from '../src/lib/redis.js';
import { setTransporterForTests } from '../src/services/mailer.js';
import { FakeRedis } from './helpers/fakeRedis.js';
import { enqueueScan } from '../src/lib/queue.js';
import nodemailer from 'nodemailer';
import { Scan, Target } from '@smartfuzz/shared/models';

// Global setup (test/globalSetup.js) provides the shared Mongo connection.

let app;

async function authedAgent(email = 'scanner@example.com') {
  const agent = request.agent(app);
  const sent = await agent.post('/api/auth/send-otp').send({ email });
  await agent.post('/api/auth/verify-otp').send({ email, otp: sent.body.devOtp });
  return agent;
}

beforeAll(async () => {
  await Promise.all([Scan, Target].map((m) => m.init()));
  setTransporterForTests(nodemailer.createTransport({ jsonTransport: true }));
  app = createApp();
});

beforeEach(() => {
  setRedisForTests(new FakeRedis());
  vi.clearAllMocks();
});


describe('POST /api/scans — consent gate', () => {
  it('requires authentication', async () => {
    const res = await request(app).post('/api/scans').send({ targetUrl: 'https://x.com', authorized: true });
    expect(res.status).toBe(401);
  });

  it('rejects a scan without authorization=true (consent gate)', async () => {
    const agent = await authedAgent();
    const res = await agent.post('/api/scans').send({ targetUrl: 'https://x.com' });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('VALIDATION_ERROR');
  });

  it('rejects an invalid target URL', async () => {
    const agent = await authedAgent();
    const res = await agent.post('/api/scans').send({ targetUrl: 'not-a-url', authorized: true });
    expect(res.status).toBe(400);
  });

  it('creates a scan, records consent, enqueues the job', async () => {
    const agent = await authedAgent();
    const res = await agent.post('/api/scans').send({ targetUrl: 'https://target.test/app', authorized: true });
    expect(res.status).toBe(201);
    expect(res.body.scan.status).toBe('pending');
    expect(res.body.scan.scanNumber).toBe(1);
    expect(res.body.scan.targetDomain).toBe('target.test');
    expect(res.body.scan.consent.authorized).toBe(true);
    expect(enqueueScan).toHaveBeenCalledOnce();
  });

  it('increments scanNumber per target on rescan', async () => {
    const agent = await authedAgent('rescan@example.com');
    const first = await agent.post('/api/scans').send({ targetUrl: 'https://same.test/', authorized: true });
    const second = await agent.post('/api/scans').send({ targetUrl: 'https://same.test/', authorized: true });
    expect(first.body.scan.scanNumber).toBe(1);
    expect(second.body.scan.scanNumber).toBe(2);
  });
});

describe('GET /api/scans', () => {
  it('lists only the requesting user\'s scans', async () => {
    const a = await authedAgent('usera@example.com');
    const b = await authedAgent('userb@example.com');
    await a.post('/api/scans').send({ targetUrl: 'https://a.test/', authorized: true });
    await b.post('/api/scans').send({ targetUrl: 'https://b.test/', authorized: true });

    const res = await a.get('/api/scans');
    expect(res.status).toBe(200);
    expect(res.body.scans.every((s) => s.targetDomain === 'a.test')).toBe(true);
  });
});

describe('GET/DELETE /api/scans/:id — ownership', () => {
  it('404s a non-existent scan', async () => {
    const agent = await authedAgent();
    const res = await agent.get(`/api/scans/${new mongoose.Types.ObjectId()}`);
    expect(res.status).toBe(404);
  });

  it('400s an invalid id', async () => {
    const agent = await authedAgent();
    const res = await agent.get('/api/scans/not-an-id');
    expect(res.status).toBe(400);
  });

  it('forbids accessing another user\'s scan', async () => {
    const a = await authedAgent('owner@example.com');
    const b = await authedAgent('intruder@example.com');
    const created = await a.post('/api/scans').send({ targetUrl: 'https://owned.test/', authorized: true });
    const res = await b.get(`/api/scans/${created.body.scan.id}`);
    expect(res.status).toBe(403);
  });

  it('deletes an owned scan', async () => {
    const agent = await authedAgent('deleter@example.com');
    const created = await agent.post('/api/scans').send({ targetUrl: 'https://del.test/', authorized: true });
    const res = await agent.delete(`/api/scans/${created.body.scan.id}`);
    expect(res.status).toBe(200);
    expect(res.body.deleted).toBe(true);
  });
});

describe('GET /api/scans/target/:domain', () => {
  it('returns scans for a domain in scanNumber order', async () => {
    const agent = await authedAgent('cmp@example.com');
    await agent.post('/api/scans').send({ targetUrl: 'https://cmp.test/', authorized: true });
    await agent.post('/api/scans').send({ targetUrl: 'https://cmp.test/', authorized: true });
    const res = await agent.get('/api/scans/target/cmp.test');
    expect(res.status).toBe(200);
    expect(res.body.scans.map((s) => s.scanNumber)).toEqual([1, 2]);
  });
});
