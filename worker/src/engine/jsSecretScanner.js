import { SSE_EVENTS } from '@smartfuzz/shared/progress';

// JavaScript Secret Scanner (Feature 1). After the crawler collects <script src>
// URLs, this module fetches each .js file (through the SSRF-guarded HttpClient)
// and scans the raw source for exposed secrets using a regex library.
//
// Pure-ish: takes an injected `http` client and an optional `publish` callback,
// so it's unit-testable with a mocked client and never touches the live internet.
//
// SECURITY: the full matched secret value is NEVER returned or stored. Only a
// masked preview (first 8 chars + ****) leaves this module. This is a scanner,
// not a secret vault.

const MAX_JS_BYTES = 5 * 1024 * 1024; // skip files larger than 5MB
const MASK_KEEP = 8; // chars of a match kept before masking

// Each pattern: a human name, the severity band (also used as the CVSS subtype),
// and the regex. `severity` must be one of critical|high|medium|low — it maps
// directly to the exposed_secret subtype in shared/cvssVectors.js.
export const SECRET_PATTERNS = [
  // AWS
  { name: 'AWS Access Key ID', severity: 'critical', regex: /AKIA[0-9A-Z]{16}/g },
  { name: 'AWS Secret Access Key', severity: 'critical', regex: /(?:aws_secret|AWS_SECRET)[_\-]?(?:access[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi },
  { name: 'AWS S3 Bucket URL', severity: 'medium', regex: /https?:\/\/[a-z0-9\-]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com/gi },

  // Google / Firebase
  { name: 'Google API Key', severity: 'high', regex: /AIza[0-9A-Za-z\-_]{35}/g },
  { name: 'Google OAuth Client ID', severity: 'medium', regex: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g },
  { name: 'Firebase URL', severity: 'high', regex: /https:\/\/[a-z0-9\-]+\.firebaseio\.com/g },
  { name: 'Firebase API Key', severity: 'high', regex: /firebase[_\-]?api[_\-]?key\s*[:=]\s*['"]?([A-Za-z0-9\-_]{35,40})['"]?/gi },

  // Stripe
  { name: 'Stripe Live Secret Key', severity: 'critical', regex: /sk_live_[0-9a-zA-Z]{24,}/g },
  { name: 'Stripe Live Public Key', severity: 'medium', regex: /pk_live_[0-9a-zA-Z]{24,}/g },
  { name: 'Stripe Test Key', severity: 'low', regex: /sk_test_[0-9a-zA-Z]{24,}/g },

  // GitHub
  { name: 'GitHub Personal Token', severity: 'critical', regex: /ghp_[A-Za-z0-9]{36}/g },
  { name: 'GitHub OAuth Token', severity: 'critical', regex: /gho_[A-Za-z0-9]{36}/g },
  { name: 'GitHub Actions Token', severity: 'critical', regex: /ghs_[A-Za-z0-9]{36}/g },
  { name: 'GitHub Classic Token', severity: 'critical', regex: /[gG]it[hH]ub[_\-]?token\s*[:=]\s*['"]?([a-f0-9]{40})['"]?/g },

  // Slack
  { name: 'Slack Bot Token', severity: 'high', regex: /xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}/g },
  { name: 'Slack User Token', severity: 'high', regex: /xoxp-[0-9]{11,13}-[0-9]{11,13}-[0-9]{11,13}-[a-f0-9]{32}/g },
  { name: 'Slack Webhook', severity: 'medium', regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9]{8,}\/B[a-zA-Z0-9]{8,}\/[a-zA-Z0-9]{24,}/g },

  // Twilio / SendGrid / Mailgun
  { name: 'Twilio Account SID', severity: 'high', regex: /AC[a-f0-9]{32}/g },
  { name: 'Twilio Auth Token', severity: 'critical', regex: /twilio[_\-]?auth[_\-]?token\s*[:=]\s*['"]?([a-f0-9]{32})['"]?/gi },
  { name: 'SendGrid API Key', severity: 'high', regex: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g },
  { name: 'Mailgun API Key', severity: 'high', regex: /key-[0-9a-zA-Z]{32}/g },

  // JWT / generic secrets
  { name: 'Hardcoded JWT Secret', severity: 'critical', regex: /jwt[_\-]?secret\s*[:=]\s*['"]([^'"]{8,})['"]|secret[_\-]?key\s*[:=]\s*['"]([^'"]{8,})['"]/gi },
  { name: 'JSON Web Token', severity: 'medium', regex: /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/g },

  // Database connection strings
  { name: 'MongoDB Connection URI', severity: 'critical', regex: /mongodb(?:\+srv)?:\/\/[^:'">\s]+:[^@'">\s]+@[^'">\s]+/gi },
  { name: 'PostgreSQL URI', severity: 'critical', regex: /postgres(?:ql)?:\/\/[^:'">\s]+:[^@'">\s]+@[^'">\s]+/gi },
  { name: 'MySQL URI', severity: 'critical', regex: /mysql:\/\/[^:'">\s]+:[^@'">\s]+@[^'">\s]+/gi },
  { name: 'Redis URI with password', severity: 'critical', regex: /redis:\/\/[^:'">\s]+:[^@'">\s]+@[^'">\s]+/gi },

  // Private IPs hardcoded
  { name: 'Internal IP Address', severity: 'low', regex: /(?:^|[^0-9])(192\.168\.[0-9]{1,3}\.[0-9]{1,3}|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3})/g },

  // Generic passwords / API keys
  { name: 'Hardcoded Password', severity: 'high', regex: /(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{6,})['"](?!\s*\+)/gi },
  { name: 'Hardcoded API Key', severity: 'high', regex: /api[_\-]?key\s*[:=]\s*['"]([A-Za-z0-9\-_]{16,})['"](?!\s*\+)/gi },

  // Azure
  { name: 'Azure Storage Key', severity: 'critical', regex: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9/+=]{88}/g },
  { name: 'Azure Client Secret', severity: 'critical', regex: /azure[_\-]?client[_\-]?secret\s*[:=]\s*['"]?([A-Za-z0-9\-_~.]{34,40})['"]?/gi },

  // Shopify
  { name: 'Shopify Token', severity: 'high', regex: /shppa_[0-9a-fA-F]{32}|shpss_[0-9a-fA-F]{32}/g },

  // npm
  { name: 'npm Access Token', severity: 'high', regex: /npm_[A-Za-z0-9]{36}/g },

  // Private key blocks
  { name: 'RSA Private Key', severity: 'critical', regex: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g },
  { name: 'PGP Private Key', severity: 'critical', regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g },
];

/** Mask a matched secret: keep the first 8 chars, append ****. Never the full value. */
export function maskSecret(value) {
  const v = String(value || '');
  if (v.length <= MASK_KEEP) return `${v}****`;
  return `${v.slice(0, MASK_KEEP)}****`;
}

/** True if a response looks like JavaScript (by content-type or .js URL). */
function looksLikeJs(url, contentType) {
  const ct = String(contentType || '').toLowerCase();
  if (ct.includes('javascript') || ct.includes('ecmascript')) return true;
  // Some servers send application/octet-stream or text/plain for .js — accept
  // by extension as long as it isn't explicitly HTML.
  if (ct.includes('html')) return false;
  try {
    return new URL(url).pathname.toLowerCase().endsWith('.js');
  } catch {
    return false;
  }
}

/** 1-based line number of a character offset within source. */
function lineAt(source, index) {
  if (index <= 0) return 1;
  let line = 1;
  for (let i = 0; i < index && i < source.length; i++) {
    if (source[i] === '\n') line++;
  }
  return line;
}

/**
 * Scan a set of JS file URLs for exposed secrets.
 * @param {object} args
 *   urls     string[]  JS file URLs (from the crawler)
 *   http     HttpClient (SSRF-guarded; injected)
 *   scanId?  for SSE progress events
 *   publish? (scanId, { kind, data }) => void   optional SSE publisher
 * @returns {Promise<object[]>} finding objects (NOT yet normalized by makeFinding)
 */
export async function scanJsSecrets({ urls = [], http, scanId, publish }) {
  const findings = [];
  const seen = new Set(); // dedup: `${url}|${patternName}|${first12}`
  let filesScanned = 0;

  for (const url of urls) {
    let res;
    try {
      // eslint-disable-next-line no-await-in-loop
      res = await http.get(url);
    } catch {
      continue; // a single bad file never kills the module
    }
    if (!res || !res.ok) continue;

    const contentType = res.headers?.['content-type'];
    if (!looksLikeJs(res.finalUrl || url, contentType)) continue;

    const source = String(res.body || '');
    if (source.length > MAX_JS_BYTES) continue;

    for (const pattern of SECRET_PATTERNS) {
      const re = new RegExp(pattern.regex.source, pattern.regex.flags.includes('g') ? pattern.regex.flags : `${pattern.regex.flags}g`);
      let m;
      while ((m = re.exec(source)) !== null) {
        // Prefer a captured group (the actual secret) over the full match.
        const captured = m.slice(1).find((g) => g != null);
        const value = captured ?? m[0];
        const dedupKey = `${url}|${pattern.name}|${String(value).slice(0, 12)}`;
        if (seen.has(dedupKey)) {
          if (m.index === re.lastIndex) re.lastIndex++; // avoid zero-width loop
          continue;
        }
        seen.add(dedupKey);

        const lineNumber = lineAt(source, m.index);
        findings.push({
          type: 'exposed_secret',
          subtype: pattern.severity, // critical|high|medium|low → CVSS subtype
          secretType: pattern.name,
          jsFileUrl: url,
          lineNumber,
          matchPreview: maskSecret(value),
          evidence: `${pattern.name} found in ${url} at line ${lineNumber}`,
          param: null,
          payload: null,
        });

        if (m.index === re.lastIndex) re.lastIndex++; // guard against zero-width matches
      }
    }

    filesScanned += 1;
    if (publish && scanId) {
      publish(scanId, {
        kind: SSE_EVENTS.PROGRESS,
        data: { currentModule: 'jsSecrets', jsFilesScanned: filesScanned, jsFilesTotal: urls.length },
      });
    }
  }

  return findings;
}
