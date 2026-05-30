import { makeFinding } from './findingFactory.js';

// Passive Analyzer (PRD §9.3) — derives findings purely from observing a normal
// response: missing security headers, version disclosure, permissive CORS,
// insecure cookies, cleartext transport, and info leakage. ZAP-ported heuristics,
// re-implemented in JS. Pure function over (url, status, headers, body) so it's
// trivially unit-testable.

const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const PRIVATE_IP_RE = /\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b/g;
const STACK_TRACE_RE =
  /(?:Traceback \(most recent call last\)|at [\w.$]+\([\w.$]+:\d+\)|java\.lang\.[A-Za-z.]+Exception|System\.[A-Za-z.]+Exception|Warning: \w+\(\)|Fatal error:|ORA-\d{5}|SQLSTATE\[)/;

// Header name → finding when ABSENT.
const SECURITY_HEADERS = [
  { header: 'content-security-policy', type: 'missing_security_header', subtype: 'csp' },
  { header: 'x-frame-options', type: 'missing_security_header', subtype: 'x_frame_options' },
  { header: 'x-content-type-options', type: 'missing_security_header', subtype: 'x_content_type_options' },
];

/** Lowercase all header keys for case-insensitive lookup. */
function normalizeHeaders(headers = {}) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) out[k.toLowerCase()] = v;
  return out;
}

/** Parse Set-Cookie (string or array) into [{ name, attrs(lowercased set) }]. */
function parseCookies(setCookie) {
  if (!setCookie) return [];
  const arr = Array.isArray(setCookie) ? setCookie : [setCookie];
  return arr.map((line) => {
    const parts = line.split(';').map((p) => p.trim());
    const [pair] = parts;
    const name = pair.split('=')[0];
    const attrs = new Set(parts.slice(1).map((p) => p.split('=')[0].toLowerCase()));
    return { name, attrs };
  });
}

/**
 * Analyze a single response. Returns an array of findings.
 * @param {object} resp { url, status, headers, body, responseTimeMs }
 */
export function analyzePassive(resp) {
  const findings = [];
  const url = resp.url || '';
  const headers = normalizeHeaders(resp.headers);
  const body = resp.body || '';
  const isHttps = url.startsWith('https://');

  const add = (f) =>
    findings.push(
      makeFinding({
        ...f,
        url,
        response: { statusCode: resp.status, headers: resp.headers, bodyExcerpt: body.slice(0, 2000), responseTimeMs: resp.responseTimeMs },
      }),
    );

  // ── Transport ──
  if (url.startsWith('http://')) {
    add({ type: 'no_https', evidence: 'Target served over cleartext HTTP' });
  }
  if (isHttps && !headers['strict-transport-security']) {
    add({ type: 'missing_hsts', evidence: 'No Strict-Transport-Security header on HTTPS response' });
  }

  // ── Security headers ──
  for (const { header, type, subtype } of SECURITY_HEADERS) {
    if (!headers[header]) {
      add({ type, subtype, evidence: `Missing ${header} header` });
    }
  }

  // ── Version / framework disclosure ──
  const server = headers.server;
  if (server && /\d/.test(server)) {
    add({ type: 'server_version_disclosure', evidence: `Server header reveals version: ${server}` });
  }
  if (headers['x-powered-by']) {
    add({ type: 'server_version_disclosure', evidence: `X-Powered-By reveals framework: ${headers['x-powered-by']}` });
  }

  // ── CORS ──
  const acao = headers['access-control-allow-origin'];
  if (acao === '*') {
    add({ type: 'cors_misconfig', evidence: 'Access-Control-Allow-Origin: * (any origin allowed)' });
  }

  // ── Cookies ──
  for (const cookie of parseCookies(headers['set-cookie'])) {
    if (!cookie.attrs.has('httponly')) {
      add({ type: 'insecure_cookie', subtype: 'missing_httponly', param: cookie.name, evidence: `Cookie "${cookie.name}" lacks HttpOnly` });
    }
    if (isHttps && !cookie.attrs.has('secure')) {
      add({ type: 'insecure_cookie', subtype: 'missing_secure', param: cookie.name, evidence: `Cookie "${cookie.name}" lacks Secure on HTTPS` });
    }
    if (!cookie.attrs.has('samesite')) {
      add({ type: 'insecure_cookie', subtype: 'missing_samesite', param: cookie.name, evidence: `Cookie "${cookie.name}" lacks SameSite` });
    }
  }

  // ── Information leakage (body) ──
  if (STACK_TRACE_RE.test(body)) {
    add({ type: 'info_disclosure', subtype: 'stack_trace', evidence: 'Response body contains a stack trace / framework error' });
  }
  const privateIps = body.match(PRIVATE_IP_RE);
  if (privateIps) {
    add({ type: 'info_disclosure', subtype: 'internal_ip', evidence: `Internal IP(s) in body: ${[...new Set(privateIps)].slice(0, 3).join(', ')}` });
  }
  const emails = body.match(EMAIL_RE);
  if (emails) {
    add({ type: 'info_disclosure', subtype: 'email', evidence: `Email address(es) in body: ${[...new Set(emails)].slice(0, 3).join(', ')}` });
  }

  return findings;
}
