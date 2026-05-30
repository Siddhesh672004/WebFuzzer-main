import { makeFinding } from './findingFactory.js';

// Auth Tester (PRD §9.6) — tests authentication-related security issues.
// Injectable http client for testing.

const DEFAULT_CREDENTIALS = [
  { user: 'admin', pass: 'admin' },
  { user: 'admin', pass: 'password' },
  { user: 'admin', pass: '123456' },
  { user: 'root', pass: 'root' },
  { user: 'test', pass: 'test' },
  { user: 'admin', pass: '' },
];

/**
 * Test authentication security on a target.
 * @param {string} targetUrl
 * @param {HttpClient} http
 * @returns {Promise<{findings: object[]}>}
 */
export async function testAuth(targetUrl, http) {
  const findings = [];

  // 1. Fetch the page and look for a login form.
  const res = await http.get(targetUrl);
  if (!res.ok) return { findings };

  const hasLoginForm = /<input[^>]+type=["']?password["']?/i.test(res.body || '');
  if (!hasLoginForm) return { findings };

  // 2. Brute-force rate-limit check — send 50 rapid requests.
  const loginUrl = extractFormAction(res.body, targetUrl);
  const rateLimitFindings = await checkRateLimit(loginUrl, http);
  findings.push(...rateLimitFindings);

  // 3. Default credentials.
  const defaultCredFindings = await checkDefaultCredentials(loginUrl, http, res.body);
  findings.push(...defaultCredFindings);

  return { findings };
}

async function checkRateLimit(loginUrl, http) {
  const findings = [];
  const ATTEMPTS = 20;
  let blocked = false;

  for (let i = 0; i < ATTEMPTS; i++) {
    // eslint-disable-next-line no-await-in-loop
    const r = await http.request({
      url: loginUrl,
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      data: 'username=test&password=test',
    });
    if (r.status === 429 || r.status === 403) {
      blocked = true;
      break;
    }
    if (!r.ok) break;
  }

  if (!blocked) {
    findings.push(
      makeFinding({
        type: 'no_rate_limit_auth',
        url: loginUrl,
        evidence: `${ATTEMPTS} rapid login attempts succeeded without rate limiting`,
      }),
    );
  }
  return findings;
}

async function checkDefaultCredentials(loginUrl, http, formHtml) {
  const findings = [];
  const userField = extractFieldName(formHtml, 'text') || 'username';
  const passField = extractFieldName(formHtml, 'password') || 'password';

  for (const cred of DEFAULT_CREDENTIALS) {
    // eslint-disable-next-line no-await-in-loop
    const r = await http.request({
      url: loginUrl,
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      data: `${encodeURIComponent(userField)}=${encodeURIComponent(cred.user)}&${encodeURIComponent(passField)}=${encodeURIComponent(cred.pass)}`,
    });

    if (isLoginSuccess(r)) {
      findings.push(
        makeFinding({
          type: 'default_credentials',
          url: loginUrl,
          evidence: `Default credentials accepted: ${cred.user}/${cred.pass || '(empty)'}`,
          response: { statusCode: r.status, bodyExcerpt: (r.body || '').slice(0, 500), responseTimeMs: r.timeMs },
        }),
      );
      break; // one confirmed finding is enough
    }
  }
  return findings;
}

function extractFormAction(html, baseUrl) {
  const m = html.match(/<form[^>]+action=["']?([^"'\s>]+)/i);
  if (m) {
    try { return new URL(m[1], baseUrl).toString(); } catch { /* fall through */ }
  }
  return baseUrl;
}

function extractFieldName(html, type) {
  const re = new RegExp(`<input[^>]+type=["']?${type}["']?[^>]+name=["']?([^"'\\s>]+)`, 'i');
  const m = html.match(re) || html.match(new RegExp(`<input[^>]+name=["']?([^"'\\s>]+)[^>]+type=["']?${type}`, 'i'));
  return m ? m[1] : null;
}

function isLoginSuccess(r) {
  if (!r.ok) return false;
  // Heuristic: redirect after POST usually means success; 200 with "logout" link.
  if (r.status >= 300 && r.status < 400) return true;
  const body = (r.body || '').toLowerCase();
  return body.includes('logout') || body.includes('dashboard') || body.includes('welcome');
}
