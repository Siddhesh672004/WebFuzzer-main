import { describe, it, expect } from 'vitest';
import { analyzeResponse } from '../src/engine/responseAnalyzer.js';
import {
  confirmStoredXss, detectJwtAlgNone, detectSessionFixation, detectIdor,
  forgeAlgNoneToken, base64UrlDecode, looksLikeJwt, extractJwt, sessionIdFromSetCookie,
} from '../src/engine/activeDetectors.js';

// Phase 9 — the 8 new detectors. Pure detectors go through analyzeResponse;
// active (multi-request) detectors get an injected fake http client so no live
// network is touched (mirrors the engine's pure-deps testing style).

const baseline = { status: 200, bodyLength: 100, responseTimeMs: 50 };
const resp = (body, status = 200, timeMs = 50, headers = {}) => ({ status, headers, body, responseTimeMs: timeMs, finalUrl: 'https://x.com/api' });

// A scripted http stub: queue of responses returned in order; records requests.
function fakeHttp(responses) {
  const calls = [];
  let i = 0;
  return {
    calls,
    async request(opts) {
      calls.push(opts);
      const r = responses[Math.min(i, responses.length - 1)];
      i += 1;
      return { ok: true, status: 200, headers: {}, body: '', timeMs: 10, ...r };
    },
    get(url, headers) { return this.request({ url, method: 'GET', headers }); },
  };
}

// ── NoSQL injection ──
describe('analyzeResponse — NoSQL injection', () => {
  it('fires on a MongoError string', () => {
    const r = analyzeResponse(baseline, resp('MongoError: cast to ObjectId failed'), { attackType: 'nosql_injection', value: '{"$gt":""}', url: 'https://x.com/api', param: 'q' });
    expect(r?.finding?.type).toBe('nosql_injection');
    expect(r?.finding?.cvssScore).toBe(8.7);
  });
  it('fires when an operator payload flips a rejected baseline to 200', () => {
    const r = analyzeResponse(
      { status: 401, bodyLength: 10, responseTimeMs: 30 },
      resp('{"user":"admin","token":"abc"}', 200),
      { attackType: 'nosql_injection', value: '{"$ne":null}', url: 'https://x.com/login', param: 'password' },
    );
    expect(r?.finding?.type).toBe('nosql_injection');
  });
  it('does NOT fire on a clean response', () => {
    const r = analyzeResponse(baseline, resp('no results found'), { attackType: 'nosql_injection', value: '{"$gt":""}', url: 'https://x.com/api', param: 'q' });
    expect(r?.finding).toBeUndefined();
  });
});

// ── XXE ──
describe('analyzeResponse — XXE', () => {
  it('fires when /etc/passwd content is echoed back', () => {
    const r = analyzeResponse(baseline, resp('<result>root:x:0:0:root:/root:/bin/bash</result>'), { attackType: 'xxe', value: '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>', url: 'https://x.com/xml', param: 'body' });
    expect(r?.finding?.type).toBe('xxe');
    expect(r?.finding?.cvssScore).toBe(9.1);
  });
  it('does NOT fire on a clean XML echo', () => {
    const r = analyzeResponse(baseline, resp('<result>ok</result>'), { attackType: 'xxe', value: '<foo/>', url: 'https://x.com/xml', param: 'body' });
    expect(r?.finding).toBeUndefined();
  });
});

// ── LDAP injection ──
describe('analyzeResponse — LDAP injection', () => {
  it('fires on an LDAP error', () => {
    const r = analyzeResponse(baseline, resp('javax.naming.directory.InvalidSearchFilterException'), { attackType: 'ldap_injection', value: '*)(uid=*', url: 'https://x.com/login', param: 'user' });
    expect(r?.finding?.type).toBe('ldap_injection');
  });
  it('does NOT fire on a clean response', () => {
    const r = analyzeResponse(baseline, resp('login failed'), { attackType: 'ldap_injection', value: '*', url: 'https://x.com/login', param: 'user' });
    expect(r?.finding).toBeUndefined();
  });
});

// ── CRLF injection ──
describe('analyzeResponse — CRLF injection', () => {
  it('fires when the injected header is reflected in response headers', () => {
    const r = analyzeResponse(
      baseline,
      resp('', 200, 50, { 'x-injected-header': 'smartfuzz' }),
      { attackType: 'crlf_injection', value: '%0d%0aX-Injected-Header:smartfuzz', url: 'https://x.com/r', param: 'next' },
    );
    expect(r?.finding?.type).toBe('crlf_injection');
    expect(r?.finding?.cvssScore).toBe(6.1);
  });
  it('does NOT fire when no injected header surfaces', () => {
    const r = analyzeResponse(baseline, resp('', 200, 50, { 'content-type': 'text/html' }), { attackType: 'crlf_injection', value: '%0d%0aX-Injected-Header:smartfuzz', url: 'https://x.com/r', param: 'next' });
    expect(r?.finding).toBeUndefined();
  });
});

// ── JWT alg:none (pure helpers + active detector) ──
describe('JWT alg:none helpers', () => {
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig';
  it('recognizes a JWT shape', () => {
    expect(looksLikeJwt(token)).toBe(true);
    expect(looksLikeJwt('not.a.jwt token')).toBe(false);
  });
  it('forges an alg:none token preserving claims', () => {
    const forged = forgeAlgNoneToken(token);
    const header = JSON.parse(base64UrlDecode(forged.split('.')[0]));
    expect(header.alg).toBe('none');
    expect(forged.endsWith('.')).toBe(true);
    expect(forged.split('.')[1]).toBe(token.split('.')[1]); // claims preserved
  });
  it('extracts a JWT from an Authorization header', () => {
    expect(extractJwt({ authorization: `Bearer ${token}` })).toBe(token);
  });
});

describe('detectJwtAlgNone', () => {
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig';
  it('fires when a 401 baseline becomes 200 with the forged token', async () => {
    const http = fakeHttp([{ status: 401 }, { status: 200, body: 'welcome admin' }]);
    const finding = await detectJwtAlgNone(http, { url: 'https://x.com/me', headers: { authorization: `Bearer ${token}` } });
    expect(finding?.type).toBe('jwt_alg_none');
  });
  it('does NOT fire when the forged token is rejected', async () => {
    const http = fakeHttp([{ status: 401 }, { status: 401 }]);
    const finding = await detectJwtAlgNone(http, { url: 'https://x.com/me', headers: { authorization: `Bearer ${token}` } });
    expect(finding).toBeNull();
  });
  it('returns null when no JWT is present', async () => {
    const http = fakeHttp([{ status: 200 }]);
    const finding = await detectJwtAlgNone(http, { url: 'https://x.com/me', headers: {} });
    expect(finding).toBeNull();
  });
});

// ── Stored XSS confirmation ──
describe('confirmStoredXss', () => {
  it('fires when the payload is served back unencoded on the view page', async () => {
    const payload = '<script>alert(1)</script>';
    const http = fakeHttp([{ status: 200 }, { status: 200, body: `comments: ${payload}` }]);
    const finding = await confirmStoredXss(http, { url: 'https://x.com/comment', param: 'body', payload });
    expect(finding?.type).toBe('xss');
    expect(finding?.subtype).toBe('stored');
  });
  it('does NOT fire when the payload is HTML-encoded on the view page', async () => {
    const payload = '<script>alert(1)</script>';
    const http = fakeHttp([{ status: 200 }, { status: 200, body: 'comments: &lt;script&gt;alert(1)&lt;/script&gt;' }]);
    const finding = await confirmStoredXss(http, { url: 'https://x.com/comment', param: 'body', payload });
    expect(finding).toBeNull();
  });
});

// ── Session fixation ──
describe('detectSessionFixation + sessionIdFromSetCookie', () => {
  it('parses a session id from Set-Cookie', () => {
    expect(sessionIdFromSetCookie(['PHPSESSID=abc123; Path=/'])).toBe('abc123');
    expect(sessionIdFromSetCookie(['other=1'])).toBeNull();
  });
  it('fires when the session id is not rotated across login', async () => {
    const http = fakeHttp([
      { status: 200, headers: { 'set-cookie': ['PHPSESSID=fixed123; Path=/'] } }, // pre-login
      { status: 200, headers: {} }, // post-login: no new cookie → not rotated
    ]);
    const finding = await detectSessionFixation(http, { url: 'https://x.com/login', params: { username: 'a', password: 'b' } });
    expect(finding?.type).toBe('session_fixation');
  });
  it('does NOT fire when the session id rotates', async () => {
    const http = fakeHttp([
      { status: 200, headers: { 'set-cookie': ['PHPSESSID=old; Path=/'] } },
      { status: 200, headers: { 'set-cookie': ['PHPSESSID=new; Path=/'] } },
    ]);
    const finding = await detectSessionFixation(http, { url: 'https://x.com/login', params: { username: 'a', password: 'b' } });
    expect(finding).toBeNull();
  });
});

// ── IDOR ──
describe('detectIdor', () => {
  it('fires when a neighbouring id returns distinct 200 content', async () => {
    const http = fakeHttp([
      { status: 200, body: 'Invoice #5 for user alice@corp.com — total $100.00, paid 2026-01-15' }, // baseline id=5
      { status: 200, body: 'Invoice #4 for user bob@corp.com — total $250.00, paid 2026-01-10' }, // id=4 — different, no denial
    ]);
    const finding = await detectIdor(http, { url: 'https://x.com/invoice?id=5', param: 'id', currentValue: 5 });
    expect(finding?.type).toBe('idor');
  });
  it('does NOT fire when other ids are access-denied', async () => {
    const http = fakeHttp([
      { status: 200, body: 'invoice for user 5' },
      { status: 200, body: 'Access denied' },
    ]);
    const finding = await detectIdor(http, { url: 'https://x.com/invoice?id=5', param: 'id', currentValue: 5 });
    expect(finding).toBeNull();
  });
});
