import { describe, it, expect } from 'vitest';
import { analyzePassive } from '../src/engine/passiveAnalyzer.js';

// A clean, secure HTTPS response — the "should NOT fire" baseline.
const secureResp = {
  url: 'https://example.com/',
  status: 200,
  headers: {
    'content-security-policy': "default-src 'self'",
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'strict-transport-security': 'max-age=31536000',
    'set-cookie': ['session=abc; HttpOnly; Secure; SameSite=Strict'],
  },
  body: '<html><body>welcome</body></html>',
  responseTimeMs: 50,
};

const types = (findings) => findings.map((f) => `${f.type}${f.subtype ? ':' + f.subtype : ''}`);

describe('analyzePassive — should NOT fire on a hardened response', () => {
  it('produces no findings for a fully secure HTTPS response', () => {
    expect(analyzePassive(secureResp)).toHaveLength(0);
  });
});

describe('analyzePassive — transport', () => {
  it('flags cleartext HTTP', () => {
    const f = analyzePassive({ ...secureResp, url: 'http://example.com/' });
    expect(types(f)).toContain('no_https');
  });

  it('flags missing HSTS on HTTPS', () => {
    const headers = { ...secureResp.headers };
    delete headers['strict-transport-security'];
    const f = analyzePassive({ ...secureResp, headers });
    expect(types(f)).toContain('missing_hsts');
  });
});

describe('analyzePassive — security headers', () => {
  it('flags each missing header', () => {
    const f = analyzePassive({ ...secureResp, headers: { 'set-cookie': ['x=1; HttpOnly; Secure; SameSite=Lax'], 'strict-transport-security': 'max-age=1' } });
    const t = types(f);
    expect(t).toContain('missing_security_header:csp');
    expect(t).toContain('missing_security_header:x_frame_options');
    expect(t).toContain('missing_security_header:x_content_type_options');
  });

  it('is case-insensitive on header names', () => {
    const f = analyzePassive({
      ...secureResp,
      headers: { 'Content-Security-Policy': "default-src 'self'", 'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff', 'Strict-Transport-Security': 'max-age=1', 'Set-Cookie': ['s=1; HttpOnly; Secure; SameSite=Strict'] },
    });
    expect(f).toHaveLength(0);
  });
});

describe('analyzePassive — disclosure', () => {
  it('flags Server version disclosure', () => {
    const f = analyzePassive({ ...secureResp, headers: { ...secureResp.headers, server: 'Apache/2.4.1' } });
    expect(types(f)).toContain('server_version_disclosure');
  });

  it('does NOT flag a Server header without a version', () => {
    const f = analyzePassive({ ...secureResp, headers: { ...secureResp.headers, server: 'cloudflare' } });
    expect(types(f)).not.toContain('server_version_disclosure');
  });

  it('flags X-Powered-By', () => {
    const f = analyzePassive({ ...secureResp, headers: { ...secureResp.headers, 'x-powered-by': 'PHP/7.2.0' } });
    expect(types(f)).toContain('server_version_disclosure');
  });
});

describe('analyzePassive — CORS', () => {
  it('flags wildcard ACAO', () => {
    const f = analyzePassive({ ...secureResp, headers: { ...secureResp.headers, 'access-control-allow-origin': '*' } });
    expect(types(f)).toContain('cors_misconfig');
  });
});

describe('analyzePassive — cookies', () => {
  it('flags missing HttpOnly/Secure/SameSite', () => {
    const f = analyzePassive({ ...secureResp, headers: { ...secureResp.headers, 'set-cookie': ['sid=xyz'] } });
    const t = types(f);
    expect(t).toContain('insecure_cookie:missing_httponly');
    expect(t).toContain('insecure_cookie:missing_secure');
    expect(t).toContain('insecure_cookie:missing_samesite');
    expect(f.find((x) => x.subtype === 'missing_httponly').param).toBe('sid');
  });
});

describe('analyzePassive — info leakage', () => {
  it('flags a stack trace in the body', () => {
    const f = analyzePassive({ ...secureResp, body: 'Fatal error: Uncaught Error in /var/www/x.php:42' });
    expect(types(f)).toContain('info_disclosure:stack_trace');
  });

  it('flags internal IPs', () => {
    const f = analyzePassive({ ...secureResp, body: 'connect to 192.168.1.50 failed' });
    expect(types(f)).toContain('info_disclosure:internal_ip');
  });

  it('flags emails', () => {
    const f = analyzePassive({ ...secureResp, body: 'contact admin@corp.internal for help' });
    expect(types(f)).toContain('info_disclosure:email');
  });

  it('does NOT flag clean body text', () => {
    const f = analyzePassive({ ...secureResp, body: 'Just a normal page with no secrets.' });
    expect(f).toHaveLength(0);
  });
});

describe('analyzePassive — finding shape', () => {
  it('produces scored findings with signature + owaspRef', () => {
    const [finding] = analyzePassive({ ...secureResp, url: 'http://example.com/' });
    expect(finding.cvssScore).toBeGreaterThan(0);
    expect(finding.severity).toBeDefined();
    expect(finding.signature).toMatch(/^[0-9a-f]{40}$/);
    expect(finding.owaspRef).toMatch(/^https:\/\/owasp\.org\//);
  });
});
