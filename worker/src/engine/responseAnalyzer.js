import { makeFinding } from './findingFactory.js';

// Response Analyzer (PRD §9.5d) — ZAP-ported detection rules. Pure function
// over (baseline, response, payloadMeta) → Finding | 'HIGH_INTEREST' | null.
// Each rule has a "should fire" and "should NOT fire" fixture in tests.

// ── SQL error patterns (ZAP pscanrules + common DB error strings) ──
const SQLI_ERROR_PATTERNS = [
  /you have an error in your sql syntax/i,
  /warning:\s*mysql/i,
  /unclosed quotation mark/i,
  /quoted string not properly terminated/i,
  /ORA-\d{5}/,
  /SQLiteException/i,
  /sqlite3\.OperationalError/i,
  /pg_query\(\).*failed/i,
  /SQLSTATE\[/i,
  /Microsoft OLE DB Provider for SQL Server/i,
  /Incorrect syntax near/i,
  /mysql_fetch_array\(\)/i,
  /supplied argument is not a valid MySQL/i,
  /Column count doesn't match/i,
  /DB2 SQL error/i,
];

// ── Path traversal / LFI confirmation ──
const LFI_PATTERNS = [
  /root:x:0:0/,
  /daemon:[^:]*:[^:]*:[^:]*:/,
  /\[boot loader\]/i,
  /\[operating systems\]/i,
  /\[fonts\]/i,
];

// ── RCE / command injection confirmation ──
const RCE_PATTERNS = [
  /uid=\d+\([^)]+\)/,
  /Volume in drive [A-Z]/i,
  /Linux version \d/i,
  /Darwin Kernel Version/i,
  /Microsoft Windows \[Version/i,
];

// ── SSTI confirmation ──
const SSTI_PATTERNS = [
  { probe: '{{7*7}}', expect: '49' },
  { probe: '${7*7}', expect: '49' },
  { probe: '#{7*7}', expect: '49' },
  { probe: '<%= 7*7 %>', expect: '49' },
];

// ── Open redirect confirmation ──
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

// ── NoSQL injection confirmation (Mongo/Couch operator-injection errors) ──
const NOSQL_ERROR_PATTERNS = [
  /MongoError/i,
  /CastError/i,
  /\bBSONError\b/i,
  /\bBSONTypeError\b/i,
  /E11000 duplicate key/i,
  /is not a function/i, // $where JS evaluation TypeError
  /MongoServerError/i,
  /failed to parse.*\$/i,
  /unknown operator: \$/i,
];

// ── XXE confirmation (file read echoed back, or entity reflected) ──
// Reuses LFI_PATTERNS for /etc/passwd-style proof; adds Windows + hostname markers.
const XXE_PATTERNS = [
  /root:x:0:0/,
  /daemon:[^:]*:[^:]*:[^:]*:/,
  /\[fonts\]/i, // win.ini
  /\[extensions\]/i, // win.ini
  /for 16-bit app support/i, // win.ini
];

// ── LDAP injection confirmation ──
const LDAP_ERROR_PATTERNS = [
  /LDAPException/i,
  /javax\.naming/i,
  /LDAP server/i,
  /com\.sun\.jndi\.ldap/i,
  /Invalid DN syntax/i,
  /supplied argument is not a valid ldap/i,
  /Bad search filter/i,
  /Protocol error occurred/i,
  /Size limit exceeded/i,
];

/**
 * Analyze a single fuzz response.
 * @param {object} baseline  { status, bodyLength, responseTimeMs }
 * @param {object} response  { status, headers, body, responseTimeMs, finalUrl }
 * @param {object} payloadMeta { type, value, attackType, url, param }
 * @returns {{ finding?: object, interest?: 'HIGH'|'MEDIUM', reason?: string } | null}
 */
export function analyzeResponse(baseline, response, payloadMeta) {
  const body = response.body || '';
  const status = response.status || 0;
  const timeMs = response.responseTimeMs || 0;
  const { attackType, value: payload, url, param } = payloadMeta;

  // ── SQLi error-based ──
  if (attackType === 'sqli' || attackType === 'auth_bypass') {
    for (const re of SQLI_ERROR_PATTERNS) {
      if (re.test(body)) {
        return {
          finding: makeFinding({
            type: 'sqli', subtype: 'error_based', url, param, payload,
            evidence: `SQL error in response: ${body.match(re)?.[0]?.slice(0, 100)}`,
            response: { statusCode: status, bodyExcerpt: body.slice(0, 2000), responseTimeMs: timeMs },
          }),
        };
      }
    }
  }

  // ── SQLi time-based (double-confirm guard: require 2× baseline) ──
  if (attackType === 'sqli' && /sleep|waitfor|pg_sleep|benchmark/i.test(payload)) {
    const threshold = Math.max(5000, (baseline.responseTimeMs || 500) * 2);
    if (timeMs > threshold) {
      return {
        finding: makeFinding({
          type: 'sqli', subtype: 'time_based', url, param, payload,
          evidence: `Response delayed ${timeMs}ms (baseline ${baseline.responseTimeMs}ms, threshold ${threshold}ms)`,
          response: { statusCode: status, bodyExcerpt: body.slice(0, 500), responseTimeMs: timeMs },
        }),
      };
    }
  }

  // ── XSS reflected — full payload must appear unencoded in the body ──
  if (attackType === 'xss') {
    if (body.includes(payload) && !isHtmlEncoded(payload, body)) {
      return {
        finding: makeFinding({
          type: 'xss', subtype: 'reflected', url, param, payload,
          evidence: `Payload reflected unencoded in response body`,
          response: { statusCode: status, bodyExcerpt: body.slice(0, 2000), responseTimeMs: timeMs },
        }),
      };
    }
  }

  // ── Path traversal / LFI ──
  if (attackType === 'path_traversal') {
    for (const re of LFI_PATTERNS) {
      if (re.test(body)) {
        return {
          finding: makeFinding({
            type: 'path_traversal', subtype: 'lfi', url, param, payload,
            evidence: `File content in response: ${body.match(re)?.[0]?.slice(0, 80)}`,
            response: { statusCode: status, bodyExcerpt: body.slice(0, 2000), responseTimeMs: timeMs },
          }),
        };
      }
    }
  }

  // ── Command injection / RCE ──
  if (attackType === 'cmd_injection') {
    for (const re of RCE_PATTERNS) {
      if (re.test(body)) {
        return {
          finding: makeFinding({
            type: 'cmd_injection', url, param, payload,
            evidence: `Command output in response: ${body.match(re)?.[0]?.slice(0, 80)}`,
            response: { statusCode: status, bodyExcerpt: body.slice(0, 2000), responseTimeMs: timeMs },
          }),
        };
      }
    }
  }

  // ── SSTI ──
  if (attackType === 'ssti') {
    for (const { probe, expect: expected } of SSTI_PATTERNS) {
      if (payload.includes(probe) && body.includes(expected)) {
        return {
          finding: makeFinding({
            type: 'ssti', url, param, payload,
            evidence: `Template expression evaluated: ${probe} → ${expected}`,
            response: { statusCode: status, bodyExcerpt: body.slice(0, 2000), responseTimeMs: timeMs },
          }),
        };
      }
    }
  }

  // ── Open redirect ──
  if (attackType === 'open_redirect' && REDIRECT_STATUSES.has(status)) {
    const location = response.headers?.location || '';
    if (location && !isSameOrigin(url, location)) {
      return {
        finding: makeFinding({
          type: 'open_redirect', url, param, payload,
          evidence: `Redirect to external URL: ${location}`,
          response: { statusCode: status, bodyExcerpt: '', responseTimeMs: timeMs },
        }),
      };
    }
  }

  // ── NoSQL injection ──
  // Confirm on operator-injection DB errors, or a $gt/$ne payload that flips a
  // baseline 401/403/empty into a 200 with a meaningfully larger body.
  if (attackType === 'nosql_injection') {
    for (const re of NOSQL_ERROR_PATTERNS) {
      if (re.test(body)) {
        return {
          finding: makeFinding({
            type: 'nosql_injection', url, param, payload,
            evidence: `NoSQL error in response: ${body.match(re)?.[0]?.slice(0, 100)}`,
            response: { statusCode: status, bodyExcerpt: body.slice(0, 2000), responseTimeMs: timeMs },
          }),
        };
      }
    }
    // Auth/data-bypass signal: operator payload turns a rejected baseline into success.
    const operatorPayload = /\$(gt|ne|regex|where|gte|lte|in)/i.test(payload);
    const baselineRejected = [401, 403, 404, 400].includes(baseline.status);
    if (operatorPayload && baselineRejected && status === 200 && body.length > (baseline.bodyLength || 0)) {
      return {
        finding: makeFinding({
          type: 'nosql_injection', url, param, payload,
          evidence: `Operator-injection payload bypassed rejection: baseline HTTP ${baseline.status} → 200 with larger body`,
          response: { statusCode: status, bodyExcerpt: body.slice(0, 2000), responseTimeMs: timeMs },
        }),
      };
    }
  }

  // ── XXE (XML External Entity) ──
  // Only meaningful for XML-accepting endpoints; confirm on file content echoed
  // back via the injected entity.
  if (attackType === 'xxe') {
    for (const re of XXE_PATTERNS) {
      if (re.test(body)) {
        return {
          finding: makeFinding({
            type: 'xxe', url, param, payload,
            evidence: `External entity resolved — file content in response: ${body.match(re)?.[0]?.slice(0, 80)}`,
            response: { statusCode: status, bodyExcerpt: body.slice(0, 2000), responseTimeMs: timeMs },
          }),
        };
      }
    }
  }

  // ── LDAP injection ──
  if (attackType === 'ldap_injection') {
    for (const re of LDAP_ERROR_PATTERNS) {
      if (re.test(body)) {
        return {
          finding: makeFinding({
            type: 'ldap_injection', url, param, payload,
            evidence: `LDAP error in response: ${body.match(re)?.[0]?.slice(0, 100)}`,
            response: { statusCode: status, bodyExcerpt: body.slice(0, 2000), responseTimeMs: timeMs },
          }),
        };
      }
    }
  }

  // ── CRLF injection / HTTP response splitting ──
  // The payload carries an injected header marker; if the server reflects user
  // input into response headers without stripping CR/LF, that header appears in
  // the parsed response headers.
  if (attackType === 'crlf_injection' && /(%0d%0a|%0D%0A|\r\n|%E5%98%8A%E5%98%8D)/.test(payload)) {
    const injected = findInjectedHeader(response.headers, payload);
    if (injected) {
      return {
        finding: makeFinding({
          type: 'crlf_injection', url, param, payload,
          evidence: `Injected header reflected in response: ${injected}`,
          response: { statusCode: status, bodyExcerpt: body.slice(0, 500), responseTimeMs: timeMs },
        }),
      };
    }
  }

  // ── Anomaly detection → HIGH_INTEREST (triggers mutation engine) ──
  if (status === 500) {
    return { interest: 'HIGH', reason: 'HTTP 500 response' };
  }
  const baseLen = baseline.bodyLength || 0;
  const respLen = body.length;
  if (baseLen > 0 && Math.abs(respLen - baseLen) / baseLen > 0.2) {
    return { interest: 'MEDIUM', reason: `Body size changed ${baseLen}→${respLen}` };
  }
  if (baseline.responseTimeMs && timeMs > baseline.responseTimeMs * 3) {
    return { interest: 'MEDIUM', reason: `Response time ${timeMs}ms vs baseline ${baseline.responseTimeMs}ms` };
  }

  return null;
}

// ── Helpers ──

function extractCanary(payload) {
  // For XSS payloads, the canary is the script/event content that would execute.
  // We look for a distinctive string that shouldn't appear in normal responses.
  const m = payload.match(/alert\(([^)]+)\)|onerror=([^\s>]+)|onload=([^\s>]+)/i);
  if (m) return m[1] || m[2] || m[3];
  // Fallback: use the raw payload if it's short enough to be distinctive.
  if (payload.length < 60) return payload;
  return null;
}

function isHtmlEncoded(str, body) {
  // If the string appears only in HTML-encoded form, it's safe.
  const encoded = str.replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  return !body.includes(str) && body.includes(encoded);
}

function isSameOrigin(base, target) {
  try {
    return new URL(base).origin === new URL(target, base).origin;
  } catch {
    return false;
  }
}

// CRLF: detect whether the payload's injected header surfaced in the parsed
// response headers. Header names are matched case-insensitively. Returns the
// matched "name: value" string for evidence, or null.
function findInjectedHeader(headers, payload) {
  if (!headers) return null;
  // Pull candidate header names out of the payload (e.g. "X-Injected-Header",
  // "Set-Cookie") that follow a CRLF sequence.
  const decoded = payload
    .replace(/%0d%0a|%0D%0A|%E5%98%8A%E5%98%8D/g, '\r\n')
    .replace(/\\r\\n/g, '\r\n');
  const matches = [...decoded.matchAll(/[\r\n]+\s*([A-Za-z][A-Za-z0-9-]*)\s*:\s*([^\r\n]*)/g)];
  for (const m of matches) {
    const name = m[1].toLowerCase();
    const wantVal = (m[2] || '').trim().toLowerCase();
    for (const [hName, hVal] of Object.entries(headers)) {
      if (hName.toLowerCase() === name) {
        const got = String(hVal).toLowerCase();
        // Confirm the value too when the payload specified one (avoids matching
        // a header the app legitimately sets).
        if (!wantVal || got.includes(wantVal) || wantVal.includes('smartfuzz')) {
          return `${hName}: ${hVal}`;
        }
      }
    }
  }
  return null;
}
