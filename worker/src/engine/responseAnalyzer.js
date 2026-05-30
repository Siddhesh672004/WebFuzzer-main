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
