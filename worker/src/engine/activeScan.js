import { detectIdor, detectJwtAlgNone, detectSessionFixation, looksLikeJwt } from './activeDetectors.js';

// Active-detector orchestration — drives the multi-request detectors in
// activeDetectors.js (IDOR, JWT alg:none, session fixation) over a crawl's
// output. Kept separate from the pure single-response analyzer so it stays
// nock/fake-http testable and so both the monolithic ScanRunner and the
// fan-out crawl handler can call the exact same logic.
//
// Every request still goes through the injected HttpClient → assertSafeUrl, so
// the SSRF defense is intact. Read-only probes (IDOR id-enumeration, forged-JWT
// replay) always run; the one mildly-intrusive probe (session fixation submits
// a single dummy login POST) is gated behind aggressiveMode.

const NUMERIC_RE = /^\d+$/;

/**
 * @param {HttpClient} http
 * @param {object} opts { endpoints[], targetUrl, aggressiveMode }
 * @returns {Promise<object[]>} normalized findings
 */
export async function runActiveDetectors(http, { endpoints = [], targetUrl, aggressiveMode = false } = {}) {
  const findings = [];

  // 1) IDOR — enumerate numeric-id query params on GET endpoints.
  const seenIdor = new Set();
  for (const ep of endpoints) {
    if ((ep.method || 'GET').toUpperCase() !== 'GET') continue;
    for (const p of ep.params || []) {
      if (p.type && p.type !== 'query') continue;
      const val = p.sampleValue;
      if (!val || !NUMERIC_RE.test(String(val))) continue;
      const key = `${ep.url}|${p.name}`;
      if (seenIdor.has(key)) continue;
      seenIdor.add(key);
      try {
        // eslint-disable-next-line no-await-in-loop
        const f = await detectIdor(http, { url: ep.url, param: p.name, currentValue: val });
        if (f) findings.push(f);
      } catch { /* ignore per-endpoint failure */ }
    }
  }

  // 2) JWT alg:none + 3) session fixation — both keyed off the target's root.
  try {
    const root = await http.get(targetUrl);
    const setCookie = root.headers?.['set-cookie'];
    const cookies = Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [];
    for (const c of cookies) {
      const m = String(c).match(/^\s*([^=]+)=([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)/);
      if (m && looksLikeJwt(m[2])) {
        const cookieName = m[1].trim();
        // eslint-disable-next-line no-await-in-loop
        const f = await detectJwtAlgNone(http, {
          url: root.finalUrl || targetUrl,
          sendVia: 'cookie',
          cookieName,
          token: m[2],
          headers: { Cookie: `${cookieName}=${m[2]}` },
        });
        if (f) findings.push(f);
        break;
      }
    }

    if (aggressiveMode) {
      const body = root.body || '';
      if (/<input[^>]+type=["']?password["']?/i.test(body)) {
        const action = extractFormAction(body, root.finalUrl || targetUrl);
        const f = await detectSessionFixation(http, {
          url: action,
          params: { username: 'smartfuzz_probe', password: 'smartfuzz_probe' },
        });
        if (f) findings.push(f);
      }
    }
  } catch { /* root fetch failed — nothing to do */ }

  return findings;
}

function extractFormAction(html, baseUrl) {
  const m = html.match(/<form[^>]+action=["']?([^"'\s>]+)/i);
  if (m) {
    try { return new URL(m[1], baseUrl).toString(); } catch { /* fall through */ }
  }
  return baseUrl;
}
