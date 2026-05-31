import { describe, it, expect } from 'vitest';
import { scanJsSecrets, maskSecret, SECRET_PATTERNS } from '../src/engine/jsSecretScanner.js';

// Fake HttpClient: a map of url → { body, contentType }. No network, no nock —
// just deterministic JS source so we can assert masking, dedupe, and line numbers.
function fakeHttp(files) {
  return {
    async get(url) {
      const f = files[url];
      if (!f) return { ok: false, error: 'ENOTFOUND', status: 0, headers: {}, body: '', finalUrl: url };
      return {
        ok: true,
        status: 200,
        headers: { 'content-type': f.contentType || 'application/javascript' },
        body: f.body,
        finalUrl: url,
      };
    },
  };
}

describe('maskSecret', () => {
  it('keeps only the first 8 chars and appends ****', () => {
    expect(maskSecret('AKIAIOSFODNN7EXAMPLE')).toBe('AKIAIOSF****');
  });
  it('handles short values without leaking the whole thing twice', () => {
    expect(maskSecret('abc')).toBe('abc****');
  });
});

describe('scanJsSecrets', () => {
  it('detects an AWS access key and masks the value', async () => {
    const files = {
      'https://x.com/app.js': { body: 'const k = "AKIAIOSFODNN7EXAMPLE";' },
    };
    const findings = await scanJsSecrets({ urls: ['https://x.com/app.js'], http: fakeHttp(files) });
    expect(findings).toHaveLength(1);
    const f = findings[0];
    expect(f.type).toBe('exposed_secret');
    expect(f.secretType).toBe('AWS Access Key ID');
    expect(f.subtype).toBe('critical');
    expect(f.jsFileUrl).toBe('https://x.com/app.js');
    expect(f.matchPreview).toBe('AKIAIOSF****');
    // The full secret must NEVER appear in any field.
    expect(JSON.stringify(f)).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('reports the correct 1-based line number', async () => {
    const body = ['// header', 'const safe = 1;', '', 'const key = "AKIAIOSFODNN7EXAMPLE";'].join('\n');
    const files = { 'https://x.com/a.js': { body } };
    const findings = await scanJsSecrets({ urls: ['https://x.com/a.js'], http: fakeHttp(files) });
    expect(findings[0].lineNumber).toBe(4);
    expect(findings[0].evidence).toContain('line 4');
  });

  it('dedupes the same secret by pattern + first-12-chars within a file', async () => {
    const body = 'a="AKIAIOSFODNN7EXAMPLE"; b="AKIAIOSFODNN7EXAMPLE";';
    const files = { 'https://x.com/dup.js': { body } };
    const findings = await scanJsSecrets({ urls: ['https://x.com/dup.js'], http: fakeHttp(files) });
    const aws = findings.filter((f) => f.secretType === 'AWS Access Key ID');
    expect(aws).toHaveLength(1);
  });

  it('detects multiple distinct secret types in one file', async () => {
    const body = [
      'const aws = "AKIAIOSFODNN7EXAMPLE";',
      'const stripe = "sk_live_0123456789abcdefABCDEF99";',
      'const gh = "ghp_0123456789abcdefABCDEFabcdef01234567";',
    ].join('\n');
    const files = { 'https://x.com/multi.js': { body } };
    const findings = await scanJsSecrets({ urls: ['https://x.com/multi.js'], http: fakeHttp(files) });
    const names = findings.map((f) => f.secretType);
    expect(names).toContain('AWS Access Key ID');
    expect(names).toContain('Stripe Live Secret Key');
    expect(names).toContain('GitHub Personal Token');
  });

  it('skips files whose content-type is HTML', async () => {
    const files = {
      'https://x.com/not-really.js': { body: 'AKIAIOSFODNN7EXAMPLE', contentType: 'text/html' },
    };
    const findings = await scanJsSecrets({ urls: ['https://x.com/not-really.js'], http: fakeHttp(files) });
    expect(findings).toHaveLength(0);
  });

  it('returns [] for an empty URL list', async () => {
    const findings = await scanJsSecrets({ urls: [], http: fakeHttp({}) });
    expect(findings).toEqual([]);
  });

  it('survives a fetch failure without throwing', async () => {
    const findings = await scanJsSecrets({ urls: ['https://x.com/gone.js'], http: fakeHttp({}) });
    expect(findings).toEqual([]);
  });

  it('publishes a progress event per scanned file', async () => {
    const files = { 'https://x.com/a.js': { body: 'var x=1;' } };
    const events = [];
    await scanJsSecrets({
      urls: ['https://x.com/a.js'],
      http: fakeHttp(files),
      scanId: 's1',
      publish: (scanId, evt) => events.push({ scanId, evt }),
    });
    expect(events.length).toBeGreaterThan(0);
    expect(events[0].evt.data.currentModule).toBe('jsSecrets');
  });

  it('every pattern severity maps to a known CVSS subtype band', () => {
    const allowed = new Set(['critical', 'high', 'medium', 'low']);
    for (const p of SECRET_PATTERNS) {
      expect(allowed.has(p.severity), `${p.name} has bad severity ${p.severity}`).toBe(true);
    }
  });
});
