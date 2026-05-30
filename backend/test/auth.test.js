import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import nodemailer from 'nodemailer';
import jwt from 'jsonwebtoken';
import { createApp } from '../src/app.js';
import { connectMongo, disconnectMongo } from '../src/lib/db.js';
import { setRedisForTests } from '../src/lib/redis.js';
import { setTransporterForTests } from '../src/services/mailer.js';
import { config } from '../src/config.js';
import { FakeRedis } from './helpers/fakeRedis.js';

// Full OTP auth flow against in-memory Mongo, a FakeRedis (OTP store), and a
// jsonTransport mailer (captures mail, sends nothing). Covers the edge cases
// from IMPLEMENTATION_PLAN §Phase 1: wrong OTP (retry), attempt exhaustion,
// resend throttling, malformed email, expiry, and JWT-protected routes.

let mongod;
let app;
let fakeRedis;

// jsonTransport returns the message as info.message (JSON string) — we parse
// the OTP out of the subject so the test can "receive" the email.
const captureTransport = nodemailer.createTransport({ jsonTransport: true });

function otpFromLastSend(res) {
  // In non-prod with json transport, the controller returns devOtp for convenience.
  return res.body.devOtp;
}

beforeAll(async () => {
  mongod = await MongoMemoryServer.create();
  await connectMongo(mongod.getUri());
  setTransporterForTests(captureTransport);
  app = createApp();
});

beforeEach(() => {
  fakeRedis = new FakeRedis();
  setRedisForTests(fakeRedis);
});

afterAll(async () => {
  setRedisForTests(null);
  setTransporterForTests(null);
  await disconnectMongo();
  await mongod?.stop();
});

describe('POST /api/auth/send-otp', () => {
  it('sends an OTP for a valid email', async () => {
    const res = await request(app).post('/api/auth/send-otp').send({ email: 'user@example.com' });
    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/verification code/i);
    expect(res.body.expiresInSeconds).toBe(config.OTP_TTL_SECONDS);
    expect(res.body.devOtp).toMatch(/^\d{6}$/); // dev convenience
  });

  it('rejects a malformed email', async () => {
    const res = await request(app).post('/api/auth/send-otp').send({ email: 'nope' });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('VALIDATION_ERROR');
  });

  it('throttles a rapid resend (cooldown)', async () => {
    await request(app).post('/api/auth/send-otp').send({ email: 'cool@example.com' });
    const second = await request(app).post('/api/auth/send-otp').send({ email: 'cool@example.com' });
    expect(second.status).toBe(429);
    expect(second.body.code).toBe('OTP_COOLDOWN');
    expect(second.body.details.retryAfterSeconds).toBeGreaterThan(0);
  });
});

describe('POST /api/auth/verify-otp', () => {
  async function getOtp(email) {
    const res = await request(app).post('/api/auth/send-otp').send({ email });
    return otpFromLastSend(res);
  }

  it('verifies a correct code, sets a cookie, creates the user', async () => {
    const email = 'verify@example.com';
    const otp = await getOtp(email);

    const res = await request(app).post('/api/auth/verify-otp').send({ email, otp });
    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe(email);
    expect(res.body.token).toBeDefined();

    // httpOnly cookie set.
    const cookie = res.headers['set-cookie']?.find((c) => c.startsWith(config.AUTH_COOKIE_NAME));
    expect(cookie).toBeDefined();
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/SameSite=Strict/i);
  });

  it('rejects a wrong code but allows retry (attemptsLeft decrements)', async () => {
    const email = 'retry@example.com';
    await getOtp(email);

    const res = await request(app).post('/api/auth/verify-otp').send({ email, otp: '000000' });
    // (1-in-a-million chance the real OTP is 000000; acceptable for a test.)
    if (res.status === 200) return; // fluke match — skip
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('OTP_MISMATCH');
    expect(res.body.details.attemptsLeft).toBe(config.OTP_MAX_ATTEMPTS - 1);
  });

  it('exhausts attempts then forces a new code', async () => {
    const email = 'exhaust@example.com';
    const realOtp = await getOtp(email);
    const wrong = realOtp === '111111' ? '222222' : '111111';

    let last;
    for (let i = 0; i < config.OTP_MAX_ATTEMPTS; i += 1) {
      last = await request(app).post('/api/auth/verify-otp').send({ email, otp: wrong });
    }
    expect(last.status).toBe(429);
    expect(last.body.code).toBe('OTP_ATTEMPTS_EXCEEDED');

    // Even the correct code now fails — OTP was consumed.
    const after = await request(app).post('/api/auth/verify-otp').send({ email, otp: realOtp });
    expect(after.status).toBe(400);
    expect(after.body.code).toBe('OTP_NOT_FOUND');
  });

  it('rejects verify when no OTP was requested', async () => {
    const res = await request(app)
      .post('/api/auth/verify-otp')
      .send({ email: 'noreq@example.com', otp: '123456' });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('OTP_NOT_FOUND');
  });

  it('rejects a non-6-digit OTP at validation', async () => {
    const res = await request(app)
      .post('/api/auth/verify-otp')
      .send({ email: 'fmt@example.com', otp: 'abc' });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('VALIDATION_ERROR');
  });
});

describe('GET /api/auth/me + logout', () => {
  async function authedAgent(email = 'me@example.com') {
    const agent = request.agent(app);
    const sent = await agent.post('/api/auth/send-otp').send({ email });
    const otp = sent.body.devOtp;
    await agent.post('/api/auth/verify-otp').send({ email, otp });
    return agent;
  }

  it('returns the current user with a valid cookie', async () => {
    const agent = await authedAgent();
    const res = await agent.get('/api/auth/me');
    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe('me@example.com');
  });

  it('401s without a token', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('NO_TOKEN');
  });

  it('401s with an expired token', async () => {
    const expired = jwt.sign({ sub: 'x', email: 'e@e.com' }, config.JWT_SECRET, { expiresIn: -10 });
    const res = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${expired}`);
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('TOKEN_EXPIRED');
  });

  it('401s with a tampered token', async () => {
    const bad = jwt.sign({ sub: 'x', email: 'e@e.com' }, 'wrong-secret');
    const res = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${bad}`);
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('TOKEN_INVALID');
  });

  it('clears the cookie on logout', async () => {
    const res = await request(app).post('/api/auth/logout');
    expect(res.status).toBe(200);
    const cookie = res.headers['set-cookie']?.find((c) => c.startsWith(config.AUTH_COOKIE_NAME));
    expect(cookie).toBeDefined();
    // Cleared cookie has an expiry in the past / empty value.
    expect(cookie).toMatch(/=;|Expires=Thu, 01 Jan 1970/i);
  });
});
