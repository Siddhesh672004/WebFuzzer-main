import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';

// Mock the queue lib so /verify enqueues against a spy, not a live BullMQ.
vi.mock('../src/lib/queue.js', () => ({
  enqueueScan: vi.fn(() => Promise.resolve({ id: 'job1' })),
  enqueueVerifyFix: vi.fn(() => Promise.resolve({ id: 'verify-job-1' })),
  getQueue: vi.fn(),
  closeQueues: vi.fn(),
}));

import { createApp } from '../src/app.js';
import { setRedisForTests } from '../src/lib/redis.js';
import { setTransporterForTests } from '../src/services/mailer.js';
import { FakeRedis } from './helpers/fakeRedis.js';
import { enqueueVerifyFix } from '../src/lib/queue.js';
import nodemailer from 'nodemailer';
import { Scan, Target, Vulnerability } from '@smartfuzz/shared/models';
import { signature } from '@smartfuzz/shared/signatures';

let app;

async function authedAgent(email = 'vuln@example.com') {
  const agent = request.agent(app);
  const sent = await agent.post('/api/auth/send-otp').send({ email });
  await agent.post('/api/auth/verify-otp').send({ email, otp: sent.body.devOtp });
  return agent;
}

// Create a scan owned by the agent + a couple of findings, return ids.
async function seedScan(agent, { domain = 'vuln.test' } = {}) {
  const res = await agent.post('/api/scans').send({ targetUrl: `https://${domain}/app`, authorized: true });
  const scanId = res.body.scan.id;
  const mk = (type, sev, score, url, param, evidence) => ({
    scanId,
    signature: signature(type, url, param),
    type, severity: sev, cvssScore: score, cvssVector: '',
    url, param, payload: "' OR 1=1--", evidence,
  });
  const inserted = await Vulnerability.insertMany([
    mk('sqli', 'critical', 10, `https://${domain}/login`, 'user', "SQL syntax error near '1'"),
    mk('xss', 'medium', 6.1, `https://${domain}/search`, 'q', 'Reflected payload'),
  ]);
  return { scanId, vulns: inserted };
}

beforeAll(async () => {
  await Promise.all([Scan, Target, Vulnerability].map((m) => m.init()));
  setTransporterForTests(nodemailer.createTransport({ jsonTransport: true }));
  app = createApp();
});

beforeEach(() => {
  setRedisForTests(new FakeRedis());
  vi.clearAllMocks();
});

describe('GET /api/scans/:id/vulnerabilities — filters', () => {
  it('returns all findings sorted by cvssScore desc', async () => {
    const agent = await authedAgent('list@example.com');
    const { scanId } = await seedScan(agent);
    const res = await agent.get(`/api/scans/${scanId}/vulnerabilities`);
    expect(res.status).toBe(200);
    expect(res.body.vulnerabilities).toHaveLength(2);
    expect(res.body.vulnerabilities[0].cvssScore).toBe(10); // sorted desc
  });

  it('filters by severity', async () => {
    const agent = await authedAgent('sev@example.com');
    const { scanId } = await seedScan(agent);
    const res = await agent.get(`/api/scans/${scanId}/vulnerabilities?severity=medium`);
    expect(res.status).toBe(200);
    expect(res.body.vulnerabilities).toHaveLength(1);
    expect(res.body.vulnerabilities[0].type).toBe('xss');
  });

  it('filters by fuzzy search on url/param', async () => {
    const agent = await authedAgent('search@example.com');
    const { scanId } = await seedScan(agent);
    const res = await agent.get(`/api/scans/${scanId}/vulnerabilities?search=login`);
    expect(res.status).toBe(200);
    expect(res.body.vulnerabilities).toHaveLength(1);
    expect(res.body.vulnerabilities[0].url).toContain('/login');
  });
});

describe('GET /api/scans/:id/vulnerabilities/:vulnId — detail + fix guide', () => {
  it('returns the finding enriched with its fix guide', async () => {
    const agent = await authedAgent('detail@example.com');
    const { scanId, vulns } = await seedScan(agent);
    const res = await agent.get(`/api/scans/${scanId}/vulnerabilities/${vulns[0].id}`);
    expect(res.status).toBe(200);
    expect(res.body.vulnerability.type).toBe('sqli');
    expect(res.body.vulnerability.fixGuide).toBeDefined();
    expect(res.body.vulnerability.fixGuide.what).toBeTruthy();
  });

  it('404s a vuln that is not in the scan', async () => {
    const agent = await authedAgent('missing@example.com');
    const { scanId } = await seedScan(agent);
    const res = await agent.get(`/api/scans/${scanId}/vulnerabilities/${new mongoose.Types.ObjectId()}`);
    expect(res.status).toBe(404);
  });
});

describe('POST /api/vulnerabilities/:vulnId/mark-fixed', () => {
  it('marks a finding fixed by the user', async () => {
    const agent = await authedAgent('mark@example.com');
    const { vulns } = await seedScan(agent);
    const res = await agent.post(`/api/vulnerabilities/${vulns[0].id}/mark-fixed`).send({ fixed: true });
    expect(res.status).toBe(200);
    expect(res.body.vulnerability.markedFixedByUser).toBe(true);
    expect(res.body.vulnerability.markedFixedAt).toBeTruthy();
  });

  it('can toggle the flag back off', async () => {
    const agent = await authedAgent('toggle@example.com');
    const { vulns } = await seedScan(agent);
    await agent.post(`/api/vulnerabilities/${vulns[0].id}/mark-fixed`).send({ fixed: true });
    const res = await agent.post(`/api/vulnerabilities/${vulns[0].id}/mark-fixed`).send({ fixed: false });
    expect(res.body.vulnerability.markedFixedByUser).toBe(false);
  });

  it('forbids marking another user\'s finding', async () => {
    const owner = await authedAgent('owner2@example.com');
    const intruder = await authedAgent('intruder2@example.com');
    const { vulns } = await seedScan(owner);
    const res = await intruder.post(`/api/vulnerabilities/${vulns[0].id}/mark-fixed`).send({ fixed: true });
    expect(res.status).toBe(403);
  });
});

describe('POST /api/vulnerabilities/:vulnId/verify', () => {
  it('enqueues a verify-fix job and sets pending', async () => {
    const agent = await authedAgent('verify@example.com');
    const { vulns } = await seedScan(agent);
    const res = await agent.post(`/api/vulnerabilities/${vulns[0].id}/verify`).send();
    expect(res.status).toBe(202);
    expect(res.body.status).toBe('queued');
    expect(res.body.jobId).toBeTruthy();
    expect(enqueueVerifyFix).toHaveBeenCalledOnce();

    // The finding is marked pending in the DB.
    const reloaded = await Vulnerability.findById(vulns[0].id);
    expect(reloaded.verificationStatus).toBe('pending');
  });

  it('400s an invalid vuln id', async () => {
    const agent = await authedAgent('badid@example.com');
    const res = await agent.post('/api/vulnerabilities/not-an-id/verify').send();
    expect(res.status).toBe(400);
  });
});

describe('GET /api/reports/:scanId/json', () => {
  it('requires auth', async () => {
    const res = await request(app).get(`/api/reports/${new mongoose.Types.ObjectId()}/json`);
    expect(res.status).toBe(401);
  });
});
