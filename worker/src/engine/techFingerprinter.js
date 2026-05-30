import * as cheerio from 'cheerio';
import { makeFinding } from './findingFactory.js';
import { matchCves } from '../knowledge/cveDatabase.js';

// Tech Fingerprinter (PRD §9.7). Detects framework/server/library + version
// from headers, meta generator tags, cookie names, URL patterns, and JS file
// paths, then matches detected versions against the local CVE database. Pure
// over (url, headers, body) for easy testing.

// Regexes that pull a tech + optional version from a string.
const HEADER_SIGS = [
  { key: 'server', re: /([A-Za-z-]+)\/([\d.]+)/, techIndex: 1, verIndex: 2 },
  { key: 'x-powered-by', re: /([A-Za-z.\- ]+?)\/?([\d.]+)?$/, techIndex: 1, verIndex: 2 },
  { key: 'x-generator', re: /([A-Za-z]+)\s*([\d.]+)?/, techIndex: 1, verIndex: 2 },
];

// Cookie name → tech (no version, just stack identification).
const COOKIE_SIGS = [
  { re: /^PHPSESSID$/i, tech: 'php' },
  { re: /^JSESSIONID$/i, tech: 'java' },
  { re: /^laravel_session$/i, tech: 'laravel' },
  { re: /^ASP\.NET_SessionId$/i, tech: 'asp.net' },
  { re: /^wordpress_/i, tech: 'wordpress' },
];

// URL/path patterns in body → tech.
const PATH_SIGS = [
  { re: /\/wp-(content|includes)\//, tech: 'wordpress' },
  { re: /\/sites\/(default|all)\//, tech: 'drupal' },
  { re: /\/_next\//, tech: 'next.js' },
  { re: /\/static\/js\/main\.[a-f0-9]+\.js/, tech: 'react' },
];

// JS library file references → tech + version (e.g. jquery-3.4.1.min.js).
const JS_LIB_RE = /\/([a-z][a-z0-9-]*?)[-.@]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/gi;

/** Merge a detection into the map, preferring entries that carry a version. */
function record(map, tech, version, source) {
  const key = tech.toLowerCase().trim();
  if (!key) return;
  const existing = map.get(key);
  if (!existing || (!existing.version && version)) {
    map.set(key, { tech: key, version: version || existing?.version || '', source });
  }
}

/**
 * Fingerprint a response. Returns { technologies: [{tech,version,source}], findings }.
 * findings = one tech_fingerprint (informational) per tech + one known_cve per match.
 */
export function fingerprint({ url = '', headers = {}, body = '' }) {
  const lower = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = Array.isArray(v) ? v.join('; ') : String(v);

  const map = new Map();

  // Headers.
  for (const sig of HEADER_SIGS) {
    const val = lower[sig.key];
    if (!val) continue;
    const m = val.match(sig.re);
    if (m && m[sig.techIndex]) record(map, m[sig.techIndex], m[sig.verIndex], `header:${sig.key}`);
  }

  // Cookies.
  const setCookie = lower['set-cookie'];
  if (setCookie) {
    for (const sig of COOKIE_SIGS) {
      const names = setCookie.split(/[;,]/).map((c) => c.trim().split('=')[0]);
      if (names.some((n) => sig.re.test(n))) record(map, sig.tech, '', 'cookie');
    }
  }

  // Meta generator + path/JS patterns from the body.
  if (body) {
    const $ = cheerio.load(body);
    const gen = $('meta[name="generator"]').attr('content');
    if (gen) {
      const m = gen.match(/([A-Za-z]+)\s*([\d.]+)?/);
      if (m) record(map, m[1], m[2], 'meta:generator');
    }
    for (const sig of PATH_SIGS) {
      if (sig.re.test(body)) record(map, sig.tech, '', 'path');
    }
    let jm;
    JS_LIB_RE.lastIndex = 0;
    // eslint-disable-next-line no-cond-assign
    while ((jm = JS_LIB_RE.exec(body)) !== null) {
      record(map, jm[1], jm[2], 'js-file');
    }
  }

  const technologies = [...map.values()];
  const findings = [];

  for (const t of technologies) {
    // Informational fingerprint finding.
    findings.push(
      makeFinding({
        type: 'tech_fingerprint',
        url,
        evidence: `Detected ${t.tech}${t.version ? ' ' + t.version : ''} (via ${t.source})`,
      }),
    );
    // CVE matches for the detected version.
    for (const cve of matchCves(t.tech, t.version)) {
      findings.push(
        makeFinding({
          type: 'known_cve',
          url,
          cveId: cve.cve,
          cvssScore: cve.cvss,
          evidence: `${t.tech} ${t.version} is affected by ${cve.cve}: ${cve.desc}`,
        }),
      );
    }
  }

  return { technologies, findings };
}
