import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { Scan, Endpoint, Vulnerability, User } from '@smartfuzz/shared/models';
import { ScanRunner } from '../src/scan/scanRunner.js';

// Drives the full Phase-2 pipeline against in-memory Mongo with a scripted fake
// HttpClient (no network). Verifies endpoints persist, findings dedupe, progress
// reaches 100%, scan stats roll up, and SSE events are emitted.

let mongod;

// Scripted target: a home page that links to /search?q= and exposes /.env,
// served by a vulnerable Apache with a missing CSP and an insecure cookie.
function scriptedHttp() {
  const homeBody = `<html><head><meta name="generator" content="WordPress 5.8.1"></head>
    <body><a href="/search?q=test">search</a><a href="/about">about</a></body></html>`;
  return {
    async get(url) {
      const u = new URL(url);
      const base = { ok: true, headers: { 'content-type': 'text/html', server: 'Apache/2.4.49', 'set-cookie': 'sid=1' }, timeMs: 10, finalUrl: url };
      if (u.pathname === '/' || u.pathname === '') return { ...base, status: 200, body: homeBody };
      if (u.pathname === '/about') return { ...base, status: 200, body: '<html>about</html>' };
      if (u.pathname === '/search') return { ...base, status: 200, body: '<html>results</html>' };
      if (u.pathname === '/.env') return { ...base, status: 200, body: 'DB_PASSWORD=' + 'x'.repeat(300), headers: { 'content-type': 'text/plain' } };
      // Everything else (incl. random soft-404 probes) → hard 404.
      return { ...base, status: 404, body: 'Not Found' };
    },
  };
}

beforeAll(async () => {
  mongod = await MongoMemoryServer.create();
  await mongoose.connect(mongod.getUri());
  await Promise.all([Scan, Endpoint, Vulnerability, User].map((m) => m.init()));
});

afterEach(async () => {
  await Promise.all([Scan, Endpoint, Vulnerability].map((m) => m.deleteMany({})));
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongod?.stop();
});

async function makeScan() {
  return Scan.create({
    userId: new mongoose.Types.ObjectId(),
    targetUrl: 'https://victim.test/',
    targetDomain: 'victim.test',
    scanNumber: 1,
    consent: { authorized: true, confirmedAt: new Date(), userId: new mongoose.Types.ObjectId() },
  });
}

describe('ScanRunner', () => {
  it('runs all modules, persists endpoints + findings, completes', async () => {
    const scan = await makeScan();
    const events = [];
    const runner = new ScanRunner({
      scanId: scan._id,
      targetUrl: 'https://victim.test/',
      http: scriptedHttp(),
      publish: (_id, ev) => events.push(ev),
      config: { maxDepth: 1, rateLimit: 1000 },
    });

    const summary = await runner.run();

    expect(summary.status).toBe('completed');
    // Endpoints discovered (search?q= form/link).
    const endpoints = await Endpoint.find({ scanId: scan._id });
    expect(endpoints.length).toBeGreaterThan(0);
    expect(endpoints.some((e) => e.url.includes('/search'))).toBe(true);

    // Findings: exposed .env + passive (missing headers/cookie) + tech CVEs.
    const vulns = await Vulnerability.find({ scanId: scan._id });
    const types = vulns.map((v) => v.type);
    expect(types).toContain('exposed_sensitive_file'); // /.env
    expect(types).toContain('known_cve'); // Apache 2.4.49 + WordPress
    expect(types).toContain('missing_security_header'); // passive

    // Scan doc updated.
    const updated = await Scan.findById(scan._id);
    expect(updated.status).toBe('completed');
    expect(updated.progress.percentComplete).toBe(100);
    expect(updated.stats.totalVulnerabilities).toBe(vulns.length);
  });

  it('emits progress, finding, module, and done SSE events', async () => {
    const scan = await makeScan();
    const events = [];
    const runner = new ScanRunner({
      scanId: scan._id,
      targetUrl: 'https://victim.test/',
      http: scriptedHttp(),
      publish: (_id, ev) => events.push(ev),
      config: { maxDepth: 1, rateLimit: 1000 },
    });
    await runner.run();

    const kinds = new Set(events.map((e) => e.kind));
    expect(kinds.has('status')).toBe(true);
    expect(kinds.has('module')).toBe(true);
    expect(kinds.has('progress')).toBe(true);
    expect(kinds.has('finding')).toBe(true);
    expect(kinds.has('done')).toBe(true);
  });

  it('dedupes findings by signature within a scan', async () => {
    const scan = await makeScan();
    const runner = new ScanRunner({
      scanId: scan._id,
      targetUrl: 'https://victim.test/',
      http: scriptedHttp(),
      config: { maxDepth: 1, rateLimit: 1000 },
    });
    await runner.run();
    // Run the passive module twice — no duplicate vuln docs should appear.
    const before = await Vulnerability.countDocuments({ scanId: scan._id });
    await runner.runPassive();
    const after = await Vulnerability.countDocuments({ scanId: scan._id });
    expect(after).toBe(before);
  });

  it('does not crash when the target is unreachable', async () => {
    const scan = await makeScan();
    const deadHttp = { async get() { return { ok: false, error: 'ECONNREFUSED', status: 0, headers: {}, body: '' }; } };
    const runner = new ScanRunner({
      scanId: scan._id,
      targetUrl: 'https://dead.test/',
      http: deadHttp,
      config: { maxDepth: 1, rateLimit: 1000 },
    });
    const summary = await runner.run();
    expect(summary.status).toBe('completed'); // graceful, partial
    expect(summary.vulnerabilities).toBe(0);
  });
});
