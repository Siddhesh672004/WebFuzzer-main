import { describe, it, expect } from 'vitest';
import { classifyParam, classifyEndpoint, PARAM_CATEGORIES } from '../src/engine/paramClassifier.js';
import { analyzeResponse } from '../src/engine/responseAnalyzer.js';
import { mutate } from '../src/engine/mutationEngine.js';

// ── Parameter Classifier ──
describe('classifyParam', () => {
  it('maps id/uid to NUMERIC_ID', () => {
    expect(classifyParam('id').category).toBe(PARAM_CATEGORIES.NUMERIC_ID);
    expect(classifyParam('user_id').category).toBe(PARAM_CATEGORIES.NUMERIC_ID);
    expect(classifyParam('product_id').category).toBe(PARAM_CATEGORIES.NUMERIC_ID);
  });
  it('maps search/q to SEARCH_FIELD', () => {
    expect(classifyParam('q').category).toBe(PARAM_CATEGORIES.SEARCH_FIELD);
    expect(classifyParam('search').category).toBe(PARAM_CATEGORIES.SEARCH_FIELD);
  });
  it('maps file/path to FILE_PATH', () => {
    expect(classifyParam('file').category).toBe(PARAM_CATEGORIES.FILE_PATH);
    expect(classifyParam('filepath').category).toBe(PARAM_CATEGORIES.FILE_PATH);
  });
  it('maps redirect/url to URL_FIELD', () => {
    expect(classifyParam('redirect').category).toBe(PARAM_CATEGORIES.URL_FIELD);
    expect(classifyParam('next').category).toBe(PARAM_CATEGORIES.URL_FIELD);
  });
  it('maps hidden inputType to HIDDEN_FIELD regardless of name', () => {
    expect(classifyParam('anything', 'hidden').category).toBe(PARAM_CATEGORIES.HIDDEN_FIELD);
  });
  it('maps email inputType to EMAIL', () => {
    expect(classifyParam('contact', 'email').category).toBe(PARAM_CATEGORIES.EMAIL);
  });
  it('maps cmd/exec to COMMAND', () => {
    expect(classifyParam('cmd').category).toBe(PARAM_CATEGORIES.COMMAND);
    expect(classifyParam('exec').category).toBe(PARAM_CATEGORIES.COMMAND);
  });
  it('maps username/password to AUTH_FIELD', () => {
    expect(classifyParam('username').category).toBe(PARAM_CATEGORIES.AUTH_FIELD);
    expect(classifyParam('password').category).toBe(PARAM_CATEGORIES.AUTH_FIELD);
  });
  it('maps price/amount to NUMERIC_BUSINESS', () => {
    expect(classifyParam('price').category).toBe(PARAM_CATEGORIES.NUMERIC_BUSINESS);
    expect(classifyParam('amount').category).toBe(PARAM_CATEGORIES.NUMERIC_BUSINESS);
  });
  it('maps role/admin to PRIVILEGE_FIELD', () => {
    expect(classifyParam('role').category).toBe(PARAM_CATEGORIES.PRIVILEGE_FIELD);
    expect(classifyParam('admin').category).toBe(PARAM_CATEGORIES.PRIVILEGE_FIELD);
  });
  it('falls back to GENERIC for unknown params', () => {
    expect(classifyParam('xyz_unknown_param').category).toBe(PARAM_CATEGORIES.GENERIC);
  });
  it('classifyEndpoint enriches all params', () => {
    const ep = { url: 'https://x.com/search', method: 'GET', params: [{ name: 'q', inputType: 'text' }, { name: 'csrf', inputType: 'hidden' }] };
    const result = classifyEndpoint(ep);
    expect(result.params[0].category).toBe(PARAM_CATEGORIES.SEARCH_FIELD);
    expect(result.params[1].category).toBe(PARAM_CATEGORIES.HIDDEN_FIELD);
  });
});

// ── Response Analyzer ──
const baseline = { status: 200, bodyLength: 100, responseTimeMs: 50 };
const resp = (body, status = 200, timeMs = 50, headers = {}) => ({ status, headers, body, responseTimeMs: timeMs, finalUrl: 'https://x.com/search' });

describe('analyzeResponse — SQLi error-based', () => {
  it('fires on MySQL error string', () => {
    const r = analyzeResponse(baseline, resp("You have an error in your SQL syntax near '1'"), { attackType: 'sqli', value: "'", url: 'https://x.com', param: 'id' });
    expect(r?.finding?.type).toBe('sqli');
    expect(r?.finding?.subtype).toBe('error_based');
  });
  it('fires on SQLSTATE error', () => {
    const r = analyzeResponse(baseline, resp('SQLSTATE[42000]: Syntax error'), { attackType: 'sqli', value: "'", url: 'https://x.com', param: 'id' });
    expect(r?.finding?.type).toBe('sqli');
  });
  it('does NOT fire on clean response', () => {
    const r = analyzeResponse(baseline, resp('Welcome to our store'), { attackType: 'sqli', value: "'", url: 'https://x.com', param: 'id' });
    expect(r?.finding).toBeUndefined();
  });
});

describe('analyzeResponse — SQLi time-based', () => {
  it('fires when response exceeds 2× baseline', () => {
    const r = analyzeResponse({ ...baseline, responseTimeMs: 100 }, resp('ok', 200, 6000), { attackType: 'sqli', value: "' AND SLEEP(5)--", url: 'https://x.com', param: 'id' });
    expect(r?.finding?.subtype).toBe('time_based');
  });
  it('does NOT fire on normal timing', () => {
    const r = analyzeResponse({ ...baseline, responseTimeMs: 100 }, resp('ok', 200, 150), { attackType: 'sqli', value: "' AND SLEEP(5)--", url: 'https://x.com', param: 'id' });
    expect(r?.finding).toBeUndefined();
  });
});

describe('analyzeResponse — XSS reflected', () => {
  it('fires when payload is reflected unencoded', () => {
    const payload = '<script>alert(1)</script>';
    const r = analyzeResponse(baseline, resp(`Results: ${payload}`), { attackType: 'xss', value: payload, url: 'https://x.com', param: 'q' });
    expect(r?.finding?.type).toBe('xss');
  });
  it('does NOT fire when payload is HTML-encoded', () => {
    const payload = '<script>alert(1)</script>';
    const r = analyzeResponse(baseline, resp('Results: &lt;script&gt;alert(1)&lt;/script&gt;'), { attackType: 'xss', value: payload, url: 'https://x.com', param: 'q' });
    expect(r?.finding).toBeUndefined();
  });
});

describe('analyzeResponse — path traversal', () => {
  it('fires on /etc/passwd content', () => {
    const r = analyzeResponse(baseline, resp('root:x:0:0:root:/root:/bin/bash'), { attackType: 'path_traversal', value: '../../etc/passwd', url: 'https://x.com', param: 'file' });
    expect(r?.finding?.type).toBe('path_traversal');
  });
});

describe('analyzeResponse — command injection', () => {
  it('fires on uid= output', () => {
    const r = analyzeResponse(baseline, resp('uid=0(root) gid=0(root)'), { attackType: 'cmd_injection', value: '; id', url: 'https://x.com', param: 'cmd' });
    expect(r?.finding?.type).toBe('cmd_injection');
  });
});

describe('analyzeResponse — SSTI', () => {
  it('fires when {{7*7}} evaluates to 49', () => {
    const r = analyzeResponse(baseline, resp('Result: 49'), { attackType: 'ssti', value: '{{7*7}}', url: 'https://x.com', param: 'template' });
    expect(r?.finding?.type).toBe('ssti');
  });
});

describe('analyzeResponse — open redirect', () => {
  it('fires on external redirect', () => {
    const r = analyzeResponse(baseline, resp('', 302, 10, { location: 'https://evil.com' }), { attackType: 'open_redirect', value: 'https://evil.com', url: 'https://x.com/go', param: 'url' });
    expect(r?.finding?.type).toBe('open_redirect');
  });
  it('does NOT fire on same-origin redirect', () => {
    const r = analyzeResponse(baseline, resp('', 302, 10, { location: 'https://x.com/home' }), { attackType: 'open_redirect', value: '/home', url: 'https://x.com/go', param: 'url' });
    expect(r?.finding).toBeUndefined();
  });
});

describe('analyzeResponse — anomaly detection', () => {
  it('returns HIGH interest on 500', () => {
    const r = analyzeResponse(baseline, resp('error', 500), { attackType: 'sqli', value: "'", url: 'https://x.com', param: 'id' });
    expect(r?.interest).toBe('HIGH');
  });
  it('returns MEDIUM interest on large body size change', () => {
    const r = analyzeResponse({ ...baseline, bodyLength: 100 }, resp('x'.repeat(500)), { attackType: 'sqli', value: "'", url: 'https://x.com', param: 'id' });
    expect(r?.interest).toBe('MEDIUM');
  });
});

// ── Mutation Engine ──
describe('mutate', () => {
  it('generates SQL bypass variants', () => {
    const variants = mutate("' OR 1=1 --", 'sqli');
    expect(variants.length).toBeGreaterThan(3);
    expect(variants.some((v) => v.includes('/**/'))).toBe(true);
    expect(variants.some((v) => v.includes('%20'))).toBe(true);
  });
  it('generates XSS bypass variants', () => {
    const variants = mutate('<script>alert(1)</script>', 'xss');
    expect(variants.some((v) => v.includes('ScRiPt') || v.includes('prompt'))).toBe(true);
  });
  it('generates traversal bypass variants', () => {
    const variants = mutate('../../etc/passwd', 'path_traversal');
    expect(variants.some((v) => v.includes('....//') || v.includes('%2f'))).toBe(true);
  });
  it('never returns the original payload', () => {
    const original = "' OR 1=1 --";
    const variants = mutate(original, 'sqli');
    expect(variants).not.toContain(original);
  });
  it('returns unique variants', () => {
    const variants = mutate("' OR 1=1 --", 'sqli');
    expect(new Set(variants).size).toBe(variants.length);
  });
});
