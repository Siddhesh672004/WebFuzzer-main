import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import path from 'path';
import { createApp } from '../src/app.js';
import { setRedisForTests } from '../src/lib/redis.js';
import { setTransporterForTests } from '../src/services/mailer.js';
import { FakeRedis } from './helpers/fakeRedis.js';
import { config } from '../src/config.js';
import nodemailer from 'nodemailer';

// Screenshots route — auth-required PNG serving with strict filename validation
// and path-traversal defense. Global setup provides the shared Mongo connection.

let app;
const dir = path.resolve(config.SCREENSHOT_DIR);
const realFile = 'abc123_def456_1700000000000.png';
// Minimal valid PNG signature bytes — enough to prove streaming works.
const PNG_BYTES = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

let emailSeq = 0;
async function authedAgent() {
  // Unique email per call avoids the OTP resend cooldown across tests (we don't
  // reset the shared FakeRedis between cases).
  const email = `shots${emailSeq++}@example.com`;
  const agent = request.agent(app);
  const sent = await agent.post('/api/auth/send-otp').send({ email });
  await agent.post('/api/auth/verify-otp').send({ email, otp: sent.body.devOtp });
  return agent;
}

beforeAll(() => {
  setRedisForTests(new FakeRedis());
  setTransporterForTests(nodemailer.createTransport({ jsonTransport: true }));
  app = createApp();
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, realFile), PNG_BYTES);
});

afterAll(() => {
  fs.rmSync(path.join(dir, realFile), { force: true });
});

describe('GET /api/screenshots/:filename', () => {
  it('requires authentication', async () => {
    const res = await request(app).get(`/api/screenshots/${realFile}`);
    expect(res.status).toBe(401);
  });

  it('serves an existing PNG to an authed user', async () => {
    const agent = await authedAgent();
    const res = await agent.get(`/api/screenshots/${realFile}`);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toBe('image/png');
    expect(res.body.slice(0, 8)).toEqual(PNG_BYTES);
  });

  it('rejects a filename that is not a simple .png (400)', async () => {
    const agent = await authedAgent();
    const res = await agent.get('/api/screenshots/evil.txt');
    expect(res.status).toBe(400);
  });

  it('rejects path-traversal attempts', async () => {
    const agent = await authedAgent();
    // Encoded traversal — the allowlist regex rejects slashes/dots outside .png.
    const res = await agent.get('/api/screenshots/%2e%2e%2fconfig.png');
    expect([400, 403, 404]).toContain(res.status);
    expect(res.status).not.toBe(200);
  });

  it('404s a well-formed but missing filename', async () => {
    const agent = await authedAgent();
    const res = await agent.get('/api/screenshots/nope_missing_123.png');
    expect(res.status).toBe(404);
  });
});
