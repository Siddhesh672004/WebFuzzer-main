import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { analyzeResponse } from '../src/engine/responseAnalyzer.js';
import { classifyParam, PARAM_CATEGORIES } from '../src/engine/paramClassifier.js';
import { runActiveDetectors } from '../src/engine/activeScan.js';
import { testAuth } from '../src/engine/authTester.js';
import { buildAuthHeaders, cookiesToHeader } from '../src/engine/authContext.js';
import { computeAggregateStats } from '../src/scoring/securityScore.js';
import { fuzzEndpoint } from '../src/engine/payloadFuzzer.js';
import {
  generateAiPayloads, parseJsonArray, _resetCircuitBreaker, _circuitOpen,
} from '../src/engine/aiPayloadGenerator.js';

// Tests for the Phase 0–6 upgrade. Same house style as the existing suites:
// pure functions get plain objects; multi-request detectors get an injected
// fake http client; no live network, no Redis, no Mongo.

const baseline = { status: 200, bodyLength: 100, responseTimeMs: 50 };
const resp = (body, status = 200, timeMs = 50, headers = {}) =>
  ({ status, headers, body, responseTimeMs: timeMs, finalUrl: 'https://x.com/api' });

// ───────────────────────── P1.1 SSRF ─────────────────────────
describe('SSRF detection (P1.1)', () => {
  const ctx = { attackType: 'ssrf', value: 'http://169.254.169.254/latest/meta-data/', url: 'https://x.com/fetch', param: 'url' };

  it('confirms on cloud-metadata content', () => {
    const r = analyzeResponse(baseline, resp('ami-id: ami-0abc\ninstance-id: i-123'), ctx);
    expect(r?.finding?.type).toBe('ssrf');
  });

  it('confirms on internal-service banner', () => {
    const r = analyzeResponse(baseline, resp('<html><body>Welcome to nginx!</body></html>'), ctx);
    expect(r?.finding?.type).toBe('ssrf');
  });

  it('flags a latency spike as HIGH_INTEREST (not a finding)', () => {
    const r = analyzeResponse(baseline, resp('nothing here', 200, 6000), ctx);
    expect(r?.finding).toBeUndefined();
    expect(r?.interest).toBe('HIGH');
  });

  it('does NOT confirm on a plain 200 with no proof', () => {
    const r = analyzeResponse(baseline, resp('a normal page of about the same size as baseline content here', 200, 60), ctx);
    expect(r?.finding).toBeUndefined();
  });

  it('routes content/fetch/src params toward ssrf', () => {
    expect(classifyParam('content').category).toBe(PARAM_CATEGORIES.FILE_PATH);
    expect(classifyParam('content').attackTypes).toContain('ssrf');
    expect(classifyParam('fetch').attackTypes).toContain('ssrf');
    expect(classifyParam('src').attackTypes).toContain('ssrf');
  });
});

// ───────────────────── P1.7 command injection ────────────────
describe('Command injection enhancements (P1.7)', () => {
  it('confirms time-based RCE on a sleep payload', () => {
    const r = analyzeResponse(baseline, resp('', 200, 6000), { attackType: 'cmd_injection', value: '; sleep 5', url: 'u', param: 'cmd' });
    expect(r?.finding?.type).toBe('cmd_injection');
  });

  it('confirms Windows RCE via COMPUTERNAME output', () => {
    const r = analyzeResponse(baseline, resp('COMPUTERNAME=WIN-SRV01\r\nUSERDOMAIN=CORP'), { attackType: 'cmd_injection', value: '& set', url: 'u', param: 'cmd' });
    expect(r?.finding?.type).toBe('cmd_injection');
  });

  it('does NOT flag a fast sleep payload', () => {
    const r = analyzeResponse(baseline, resp('ok', 200, 120), { attackType: 'cmd_injection', value: '; sleep 5', url: 'u', param: 'cmd' });
    expect(r?.finding).toBeUndefined();
  });
});

// ─────────────────── P1.6 500 stack-trace disclosure ──────────
describe('HTTP 500 stack-trace → info_disclosure (P1.6)', () => {
  it('confirms a Java stack trace on a payload-induced 500', () => {
    const body = 'java.lang.NullPointerException\n\tat com.app.Svc.handle(Svc.java:42)';
    const r = analyzeResponse(baseline, resp(body, 500), { attackType: 'sqli', value: "'", url: 'u', param: 'q' });
    expect(r?.finding?.type).toBe('info_disclosure');
    expect(r?.finding?.subtype).toBe('stack_trace');
  });

  it('confirms a Spring stack trace', () => {
    const body = 'org.springframework.web.util.NestedServletException: boom';
    const r = analyzeResponse(baseline, resp(body, 500), { attackType: 'cmd_injection', value: ';id', url: 'u', param: 'c' });
    expect(r?.finding?.type).toBe('info_disclosure');
  });

  it('a plain 500 with no trace stays HIGH_INTEREST', () => {
    const r = analyzeResponse(baseline, resp('Internal Server Error', 500), { attackType: 'sqli', value: "'", url: 'u', param: 'q' });
    expect(r?.finding).toBeUndefined();
    expect(r?.interest).toBe('HIGH');
  });
});

// ───────────────── P1.4 active detectors orchestration ────────
describe('runActiveDetectors — IDOR (P1.4)', () => {
  function routingHttp() {
    return {
      async request({ url }) {
        const u = new URL(url);
        const id = u.searchParams.get('id');
        if (id) return { ok: true, status: 200, headers: {}, body: `account ${id}: distinct profile + balance data for user ${id}`, timeMs: 10 };
        return { ok: true, status: 200, headers: {}, body: '<html>home, no login form, no jwt</html>', timeMs: 10 };
      },
      get(url, headers) { return this.request({ url, method: 'GET', headers }); },
    };
  }

  it('flags IDOR on a numeric-id query param', async () => {
    const endpoints = [{ url: 'https://t.com/item', method: 'GET', params: [{ name: 'id', type: 'query', sampleValue: '5' }] }];
    const findings = await runActiveDetectors(routingHttp(), { endpoints, targetUrl: 'https://t.com/' });
    expect(findings.some((f) => f.type === 'idor')).toBe(true);
  });

  it('returns nothing when there are no id params and no auth surface', async () => {
    const endpoints = [{ url: 'https://t.com/about', method: 'GET', params: [{ name: 'lang', type: 'query', sampleValue: 'en' }] }];
    const findings = await runActiveDetectors(routingHttp(), { endpoints, targetUrl: 'https://t.com/' });
    expect(findings.length).toBe(0);
  });
});

// ─────────────────── P1.3 XXE via the fuzzer ──────────────────
describe('Fuzzer sends XML body for XXE (P1.3)', () => {
  function fakeModel(payloads) {
    return {
      find(q) {
        const types = q.type.$in;
        const list = payloads.filter((p) => types.includes(p.type));
        return { sort() { return this; }, limit() { return this; }, lean: async () => list };
      },
      updateOne: async () => ({}),
    };
  }
  function xxeHttp() {
    return {
      async request({ data }) {
        if (data && /DOCTYPE/.test(String(data))) {
          return { ok: true, status: 200, headers: {}, body: 'root:x:0:0:root:/root:/bin/bash', timeMs: 10 };
        }
        return { ok: true, status: 200, headers: {}, body: 'ok', timeMs: 10 };
      },
      get(url) { return this.request({ url, method: 'GET' }); },
    };
  }

  it('confirms XXE when an XML POST echoes /etc/passwd', async () => {
    const endpoint = { url: 'https://t.com/api/xml', method: 'POST', params: [{ name: 'note', type: 'body', inputType: 'text' }] };
    const model = fakeModel([
      { type: 'xxe', value: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', source: 'custom', tags: [] },
    ]);
    const { findings } = await fuzzEndpoint(endpoint, xxeHttp(), { payloadModel: model });
    expect(findings.some((f) => f.type === 'xxe')).toBe(true);
  });
});

// ───────────────────── P0.4 aggressive mode ───────────────────
describe('Auth tester aggressive-mode gating (P0.4)', () => {
  function authHttp() {
    return {
      async get() {
        return { ok: true, status: 200, headers: {}, body: '<form action="/login" method="post"><input name="user" type="text"><input name="pass" type="password"></form>', timeMs: 5 };
      },
      async request() {
        return { ok: true, status: 200, headers: {}, body: 'Welcome — you are now logged in. logout', timeMs: 5 };
      },
    };
  }

  it('does NOT submit default credentials when aggressiveMode is off', async () => {
    const { findings } = await testAuth('https://t.com/', authHttp());
    expect(findings.some((f) => f.type === 'default_credentials')).toBe(false);
  });

  it('submits default credentials when aggressiveMode is on', async () => {
    const { findings } = await testAuth('https://t.com/', authHttp(), { aggressiveMode: true });
    expect(findings.some((f) => f.type === 'default_credentials')).toBe(true);
  });
});

// ───────────────────── P2.2 auth headers ──────────────────────
describe('buildAuthHeaders (P2.2)', () => {
  it('serializes custom cookies into a Cookie header', () => {
    const h = buildAuthHeaders({ customCookies: [{ name: 'sid', value: 'abc' }, { name: 'role', value: 'admin' }] });
    expect(h.Cookie).toBe('sid=abc; role=admin');
  });
  it('passes custom headers through', () => {
    const h = buildAuthHeaders({ customHeaders: { Authorization: 'Bearer t0ken' } });
    expect(h.Authorization).toBe('Bearer t0ken');
  });
  it('is empty for no auth', () => {
    expect(buildAuthHeaders({})).toEqual({});
    expect(cookiesToHeader([{ name: 'a', value: '1' }])).toBe('a=1');
  });
});

// ───────────────────── P4.5 aggregate CVSS ────────────────────
describe('computeAggregateStats (P4.5)', () => {
  it('computes max + rounded average', () => {
    expect(computeAggregateStats([{ cvssScore: 9.8 }, { cvssScore: 6.1 }])).toEqual({ maxCvssScore: 9.8, avgCvssScore: 8 });
  });
  it('ignores zero/missing scores and handles empty', () => {
    expect(computeAggregateStats([])).toEqual({ maxCvssScore: 0, avgCvssScore: 0 });
    expect(computeAggregateStats([{ cvssScore: 0 }, {}])).toEqual({ maxCvssScore: 0, avgCvssScore: 0 });
  });
});

// ───────────────────── P3.1 AI payloads ───────────────────────
describe('AI payload generator (P3.1)', () => {
  beforeEach(() => _resetCircuitBreaker());
  afterEach(() => vi.unstubAllGlobals());

  it('parseJsonArray tolerates fences and prose', () => {
    expect(parseJsonArray('```json\n["a","b"]\n```')).toEqual(['a', 'b']);
    expect(parseJsonArray('Sure! ["x","y"] done')).toEqual(['x', 'y']);
  });

  it('returns [] when mode is off (default)', async () => {
    expect(await generateAiPayloads('sqli', 'q', '')).toEqual([]);
  });

  it('returns sanitized payloads from the gemini backend', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ candidates: [{ content: { parts: [{ text: '["p1","p2","p3"]' }] } }] }),
    }));
    const out = await generateAiPayloads('xss', 'name', 'ctx', { mode: 'gemini', apiKey: 'test-key' });
    expect(out).toEqual(['p1', 'p2', 'p3']);
  });

  it('opens the circuit breaker on a 429 and then returns [] within cooldown', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 429, json: async () => ({}) }));
    const first = await generateAiPayloads('sqli', 'q', '', { mode: 'ollama', cooldownMs: 60000 });
    expect(first).toEqual([]);
    expect(_circuitOpen()).toBe(true);
    // Next call short-circuits without even calling fetch.
    const second = await generateAiPayloads('sqli', 'q', '', { mode: 'ollama', cooldownMs: 60000 });
    expect(second).toEqual([]);
  });

  it('ollama backend parses a successful response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ response: '["a","b"]' }),
    }));
    const out = await generateAiPayloads('sqli', 'id', '', { mode: 'ollama' });
    expect(out).toEqual(['a', 'b']);
  });
});
