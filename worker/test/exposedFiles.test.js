import { describe, it, expect } from 'vitest';
import { isExposed, fingerprint, scanExposedFiles } from '../src/engine/exposedFiles.js';

// Build a fake HttpClient from a path→response map. Random soft-404 probe paths
// (/sf-not-found-...) fall through to a configurable default.
function fakeHttp(map, notFound = { ok: true, status: 404, headers: {}, body: 'Not Found', timeMs: 5 }) {
  return {
    async get(url) {
      const path = new URL(url).pathname;
      for (const [p, resp] of Object.entries(map)) {
        if (path === p) return { ok: true, headers: {}, timeMs: 5, ...resp };
      }
      return notFound;
    },
  };
}

const ok = (body, status = 200) => ({ ok: true, status, headers: {}, body, timeMs: 5 });

describe('fingerprint', () => {
  it('is stable for identical responses', () => {
    expect(fingerprint(ok('same body'))).toBe(fingerprint(ok('same body')));
  });
  it('differs by status', () => {
    expect(fingerprint(ok('x', 200))).not.toBe(fingerprint(ok('x', 404)));
  });
});

describe('isExposed', () => {
  const fileEntry = { type: 'exposed_sensitive_file', desc: '.env' };
  const adminEntry = { type: 'exposed_admin_panel', desc: 'admin' };

  it('flags a 200 file on a hard-404 site', () => {
    expect(isExposed(ok('SECRET=1'), fileEntry, false, null)).toBe(true);
  });

  it('does NOT flag a non-200, non-403 status', () => {
    expect(isExposed(ok('x', 500), fileEntry, false, null)).toBe(false);
  });

  it('treats 403 as exposure only for admin panels', () => {
    expect(isExposed(ok('', 403), adminEntry, false, null)).toBe(true);
    expect(isExposed(ok('', 403), fileEntry, false, null)).toBe(false);
  });

  it('suppresses a 200 that matches the soft-404 baseline', () => {
    const baseline = ok('<html>Page not found, sorry</html>');
    const probe = ok('<html>Page not found, sorry</html>');
    expect(isExposed(probe, fileEntry, true, baseline)).toBe(false);
  });

  it('flags a 200 that differs from the soft-404 baseline', () => {
    const baseline = ok('<html>Page not found</html>'); // ~25 chars
    const real = ok('DB_PASSWORD=supersecret\n'.repeat(50)); // very different length
    expect(isExposed(real, fileEntry, true, baseline)).toBe(true);
  });

  it('honors a content matcher (e.g. /.git/HEAD must look like a git ref)', () => {
    const entry = { type: 'exposed_sensitive_file', desc: 'git', match: /^ref:|^[0-9a-f]{40}/ };
    expect(isExposed(ok('ref: refs/heads/main'), entry, false, null)).toBe(true);
    expect(isExposed(ok('<html>home page</html>'), entry, false, null)).toBe(false);
  });
});

describe('scanExposedFiles', () => {
  it('finds an exposed .env on a hard-404 site', async () => {
    const http = fakeHttp({ '/.env': ok('DB_PASS=secret') });
    const { findings, soft404 } = await scanExposedFiles('https://x.com', http, {
      paths: [{ path: '/.env', type: 'exposed_sensitive_file', desc: 'env' }],
    });
    expect(soft404).toBe(false);
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe('exposed_sensitive_file');
  });

  it('produces zero false positives on a soft-404 site', async () => {
    // Server returns 200 + same body for EVERYTHING, including random probes.
    const softBody = '<html><body>Sorry, page not found</body></html>';
    const http = {
      async get() {
        return { ok: true, status: 200, headers: {}, body: softBody, timeMs: 5 };
      },
    };
    const { findings, soft404 } = await scanExposedFiles('https://x.com', http, {
      paths: [
        { path: '/.env', type: 'exposed_sensitive_file', desc: 'env' },
        { path: '/admin', type: 'exposed_admin_panel', desc: 'admin' },
      ],
    });
    expect(soft404).toBe(true);
    expect(findings).toHaveLength(0); // all 200s match the soft-404 template
  });

  it('still finds a real file that differs on a soft-404 site', async () => {
    const softBody = 'Not found';
    const http = {
      async get(url) {
        if (new URL(url).pathname === '/.env') {
          return { ok: true, status: 200, headers: {}, body: 'SECRET_KEY=' + 'x'.repeat(500), timeMs: 5 };
        }
        return { ok: true, status: 200, headers: {}, body: softBody, timeMs: 5 };
      },
    };
    const { findings } = await scanExposedFiles('https://x.com', http, {
      paths: [{ path: '/.env', type: 'exposed_sensitive_file', desc: 'env' }],
    });
    expect(findings).toHaveLength(1);
  });
});
