import { makeFinding } from './findingFactory.js';

// Active (multi-request) detectors — PRD §9.5d, the rules that can't be decided
// from one response and therefore need follow-up round-trips. Unlike
// responseAnalyzer (pure over a single response), each function here takes the
// injected `http` client so it stays nock-testable without the live network.
//
// Every outbound request still goes through HttpClient → assertSafeUrl, so the
// SSRF defense is preserved (these never call axios/fetch directly).

// ───────────────────────── Stored XSS confirmation ─────────────────────────

/**
 * Confirm stored XSS: a payload submitted via write request is later served
 * back unencoded on a view page (or the same URL via GET).
 *
 * @param {HttpClient} http
 * @param {object} ctx { url, method, param, payload, viewUrl? }
 * @returns {Promise<object|null>} finding or null
 */
export async function confirmStoredXss(http, ctx) {
  const { url, method = 'POST', param, payload, viewUrl } = ctx;

  // 1) Submit the payload via the write request.
  const data = `${encodeURIComponent(param)}=${encodeURIComponent(payload)}`;
  await http.request({
    url,
    method,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    data,
  });

  // 2) GET the view page (defaults to the same base URL) and look for the
  //    unencoded payload in the served body.
  const target = viewUrl || url;
  const view = await http.request({ url: target, method: 'GET' });
  const body = view.body || '';

  if (body.includes(payload) && !isHtmlEncoded(payload, body)) {
    return makeFinding({
      type: 'xss',
      subtype: 'stored',
      url: target,
      param,
      payload,
      evidence: `Payload persisted and served unencoded on ${target}`,
      response: {
        statusCode: view.status,
        bodyExcerpt: body.slice(0, 2000),
        responseTimeMs: view.timeMs,
      },
    });
  }
  return null;
}

// ───────────────────────── JWT algorithm:none ──────────────────────────────

/** Base64url-encode a UTF-8 string (no padding). */
export function base64UrlEncode(str) {
  return Buffer.from(str, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/** Base64url-decode to a UTF-8 string. Returns '' on malformed input. */
export function base64UrlDecode(seg) {
  try {
    const pad = seg.length % 4 === 0 ? '' : '='.repeat(4 - (seg.length % 4));
    return Buffer.from(seg.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64').toString('utf8');
  } catch {
    return '';
  }
}

/** Looks like a JWT: three base64url segments separated by dots. */
export function looksLikeJwt(s) {
  return typeof s === 'string' && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(s);
}

/**
 * Forge an alg:none variant of a JWT: keep the original claims, rewrite the
 * header algorithm to "none", and drop the signature. Returns null if the
 * input isn't a parseable JWT.
 */
export function forgeAlgNoneToken(token) {
  if (!looksLikeJwt(token)) return null;
  const [h, p] = token.split('.');
  const header = base64UrlDecode(h);
  const payload = base64UrlDecode(p);
  if (!header || !payload) return null;
  let headerObj;
  try {
    headerObj = JSON.parse(header);
  } catch {
    return null;
  }
  headerObj.alg = 'none';
  const newHeader = base64UrlEncode(JSON.stringify(headerObj));
  // Trailing dot, empty signature — the canonical alg:none form.
  return `${newHeader}.${p}.`;
}

/** Extract the first JWT found in an Authorization header or Cookie header. */
export function extractJwt(headers = {}) {
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase();
    const v = String(value || '');
    if (lower === 'authorization') {
      const m = v.match(/Bearer\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)/i);
      if (m) return m[1];
    }
    if (lower === 'cookie') {
      const m = v.match(/([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)/);
      if (m && looksLikeJwt(m[1])) return m[1];
    }
  }
  return null;
}

/**
 * Detect JWT alg:none acceptance: replay the request with a forged alg:none
 * token. If a baseline-rejected request (401/403) becomes 200, the server is
 * trusting the unsigned token.
 *
 * @param {HttpClient} http
 * @param {object} ctx { url, method?, headers, token?, sendVia? ('header'|'cookie'), cookieName? }
 */
export async function detectJwtAlgNone(http, ctx) {
  const { url, method = 'GET', headers = {}, sendVia = 'header', cookieName = 'token' } = ctx;
  const token = ctx.token || extractJwt(headers);
  if (!token) return null;

  // Baseline with the original (valid) token.
  const baseline = await http.request({ url, method, headers });
  // Only meaningful when the endpoint actually gates on the token.
  if (![200, 401, 403].includes(baseline.status)) return null;

  const forged = forgeAlgNoneToken(token);
  if (!forged) return null;

  const forgedHeaders = { ...headers };
  if (sendVia === 'cookie') {
    forgedHeaders.Cookie = `${cookieName}=${forged}`;
  } else {
    forgedHeaders.Authorization = `Bearer ${forged}`;
  }

  const res = await http.request({ url, method, headers: forgedHeaders });

  // Confirm: forged unsigned token grants access the server should reject.
  // Either a rejected baseline flips to 200, or an authed baseline stays 200
  // with the signature stripped (server never verified it).
  const grantedFromRejected = [401, 403].includes(baseline.status) && res.status === 200;
  const acceptedUnsigned = baseline.status === 200 && res.status === 200;
  if (grantedFromRejected || acceptedUnsigned) {
    return makeFinding({
      type: 'jwt_alg_none',
      url,
      param: sendVia === 'cookie' ? cookieName : 'Authorization',
      payload: forged,
      evidence:
        `Server accepted an alg:none (unsigned) JWT: baseline HTTP ${baseline.status} → forged HTTP ${res.status}.` +
        (acceptedUnsigned ? ' Signature stripped and still accepted.' : ''),
      response: {
        statusCode: res.status,
        bodyExcerpt: (res.body || '').slice(0, 1000),
        responseTimeMs: res.timeMs,
      },
    });
  }
  return null;
}

// ───────────────────────── Session fixation ────────────────────────────────

/** Parse the session id from Set-Cookie headers for a known set of cookie names. */
export function sessionIdFromSetCookie(setCookie, names = SESSION_COOKIE_NAMES) {
  if (!setCookie) return null;
  const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
  for (const c of cookies) {
    const m = String(c).match(/^\s*([^=]+)=([^;]+)/);
    if (m && names.includes(m[1].trim().toLowerCase())) {
      return m[2].trim();
    }
  }
  return null;
}

const SESSION_COOKIE_NAMES = ['phpsessid', 'jsessionid', 'sessionid', 'session', 'connect.sid', 'sid', 'asp.net_sessionid'];

/**
 * Detect session fixation: if the session cookie issued before a login attempt
 * is identical to the one after (i.e. the server did not rotate it on auth),
 * the session can be fixed by an attacker.
 *
 * @param {HttpClient} http
 * @param {object} ctx { url, method?, params {username,password,...} }
 */
export async function detectSessionFixation(http, ctx) {
  const { url, method = 'POST', params = {} } = ctx;

  // 1) Pre-login: obtain a session cookie from the login page.
  const pre = await http.request({ url, method: 'GET' });
  const preId = sessionIdFromSetCookie(pre.headers?.['set-cookie']);
  if (!preId) return null; // no session cookie issued — nothing to fix

  // 2) Submit credentials carrying the pre-login session cookie.
  const data = Object.entries(params)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
  const post = await http.request({
    url,
    method,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Cookie: `${dominantCookieName(pre.headers?.['set-cookie']) || 'session'}=${preId}`,
    },
    data,
  });

  // 3) If the server set a NEW session id, it rotated — safe. If it set the same
  //    id back (or set none, keeping the supplied one), it's fixation-prone.
  const postId = sessionIdFromSetCookie(post.headers?.['set-cookie']);
  const rotated = postId && postId !== preId;
  if (!rotated) {
    return makeFinding({
      type: 'session_fixation',
      url,
      param: 'session',
      payload: preId.slice(0, 40),
      evidence:
        `Session id not rotated across the login boundary (pre=${preId.slice(0, 12)}…` +
        (postId ? `, post=${postId.slice(0, 12)}…)` : ', no new cookie issued)'),
      response: {
        statusCode: post.status,
        bodyExcerpt: '',
        responseTimeMs: post.timeMs,
      },
    });
  }
  return null;
}

function dominantCookieName(setCookie) {
  if (!setCookie) return null;
  const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
  for (const c of cookies) {
    const m = String(c).match(/^\s*([^=]+)=/);
    if (m && SESSION_COOKIE_NAMES.includes(m[1].trim().toLowerCase())) return m[1].trim();
  }
  return null;
}

// ───────────────────────── IDOR ────────────────────────────────────────────

const NOT_FOUND_HINTS = [
  /not found/i,
  /no such/i,
  /does not exist/i,
  /404/,
  /access denied/i,
  /forbidden/i,
  /unauthorized/i,
];

/**
 * Detect IDOR on a numeric-id parameter: request neighbouring ids and 999999.
 * If another id returns 200 with a substantial body that doesn't read as a
 * "not found / denied" page and differs from baseline, flag it for review.
 *
 * Reported at the registry severity but with evidence noting manual
 * verification is recommended (object-level authz can't be fully auto-proven).
 *
 * @param {HttpClient} http
 * @param {object} ctx { url, method?, param, currentValue }
 */
export async function detectIdor(http, ctx) {
  const { url, method = 'GET', param, currentValue } = ctx;
  const current = Number(currentValue);
  if (!Number.isFinite(current)) return null;

  // Baseline: the legitimate current id.
  const baseUrl = withParam(url, param, String(current));
  const baseline = await http.request({ url: baseUrl, method });
  if (baseline.status !== 200) return null;

  const candidates = [current - 1, current + 1, 999999].filter((n) => n >= 0 && n !== current);
  for (const id of candidates) {
    const tryUrl = withParam(url, param, String(id));
    // eslint-disable-next-line no-await-in-loop
    const res = await http.request({ url: tryUrl, method });
    const body = res.body || '';
    const looksDenied = NOT_FOUND_HINTS.some((re) => re.test(body));
    const substantial = body.length > 50;
    const differsFromBaseline = body !== baseline.body;

    if (res.status === 200 && substantial && !looksDenied && differsFromBaseline) {
      return makeFinding({
        type: 'idor',
        url: baseUrl,
        param,
        payload: String(id),
        evidence:
          `Object id ${id} (≠ current ${current}) returned HTTP 200 with distinct content and no ` +
          `authorization barrier. Manual verification recommended to confirm cross-tenant access.`,
        response: {
          statusCode: res.status,
          bodyExcerpt: body.slice(0, 1500),
          responseTimeMs: res.timeMs,
        },
      });
    }
  }
  return null;
}

function withParam(url, param, value) {
  const u = new URL(url);
  u.searchParams.set(param, value);
  return u.toString();
}

// ── Shared helper (mirrors responseAnalyzer's encoding check) ──
function isHtmlEncoded(str, body) {
  const encoded = str.replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  return !body.includes(str) && body.includes(encoded);
}
