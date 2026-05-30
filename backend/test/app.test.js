import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app.js';

// Smoke tests — global setup (test/globalSetup.js) provides the shared Mongo.

let app;

beforeAll(() => {
  app = createApp();
});

describe('health routes', () => {
  it('GET /api/ping returns pong without touching dependencies', async () => {
    const res = await request(app).get('/api/ping');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ pong: true });
  });

  it('GET /api/health reports ok when Mongo is connected', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.service).toBe('backend');
    expect(res.body.mongo).toBe('connected');
    expect(res.body.timestamp).toBeDefined();
  });
});

describe('app middleware', () => {
  it('sets security headers via helmet', async () => {
    const res = await request(app).get('/api/ping');
    // helmet sets these by default
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-dns-prefetch-control']).toBeDefined();
  });

  it('404s unknown non-auth routes with a structured error', async () => {
    const res = await request(app).get('/api/health/does-not-exist');
    expect(res.status).toBe(404);
    expect(res.body.code).toBe('ROUTE_NOT_FOUND');
  });

  it('parses JSON bodies without crashing', async () => {
    const res = await request(app).post('/api/ping').send({ hello: 'world' });
    expect([404, 401]).toContain(res.status);
  });
});
