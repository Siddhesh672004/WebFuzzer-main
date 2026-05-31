import { createHash } from 'node:crypto';
import { makeFinding } from './findingFactory.js';
import { SENSITIVE_PATHS } from '../knowledge/sensitivePaths.js';

// Exposed Files Scanner (PRD §9.4) with mandatory soft-404 detection
// (IMPLEMENTATION_PLAN §3.4). Many apps return 200 for missing pages with a
// custom "not found" body, so before trusting any 200 we fingerprint the
// response to a guaranteed-random path and only flag a sensitive path whose
// response DIFFERS from that soft-404 fingerprint.

/** Fingerprint a response by status + rounded length + content hash bucket. */
export function fingerprint(resp) {
  const body = resp.body || '';
  // Bucket length to absorb tiny dynamic differences (timestamps, csrf tokens).
  const lenBucket = Math.round(body.length / 64);
  const hash = createHash('sha1').update(body.replace(/\s+/g, ' ').trim()).digest('hex').slice(0, 16);
  return `${resp.status}:${lenBucket}:${hash}`;
}

/** True if two responses look "the same" (same soft-404 template). */
function looksSame(a, b) {
  if (a.status !== b.status) return false;
  // Same status + body length within ~10% → treat as the same template.
  const la = (a.body || '').length;
  const lb = (b.body || '').length;
  const diff = Math.abs(la - lb);
  const tolerance = Math.max(64, Math.max(la, lb) * 0.1);
  return diff <= tolerance;
}

/**
 * Establish the soft-404 baseline by requesting two guaranteed-missing random
 * paths. Returns { isSoft404, baseline } — isSoft404 true if the server returns
 * 200 for nonexistent paths (so 200 alone is meaningless).
 */
export async function detectSoft404(baseUrl, http) {
  const rnd = () => `/sf-not-found-${randHex()}-${randHex()}`;
  const a = await http.get(new URL(rnd(), baseUrl).toString());
  const b = await http.get(new URL(rnd(), baseUrl).toString());

  const isSoft404 = a.ok && a.status === 200;
  return { isSoft404, baseline: a.ok ? a : null, baselineB: b.ok ? b : null };
}

function randHex() {
  // Deterministic-enough randomness without Math.random in workflow contexts;
  // here we just need uniqueness, and this runs in the worker (Date allowed).
  return createHash('sha1').update(`${Date.now()}-${process.hrtime.bigint()}`).digest('hex').slice(0, 8);
}

/**
 * Scan a target for exposed sensitive paths.
 * @param {string} baseUrl
 * @param {HttpClient} http
 * @param {object} [opts] { paths?, onProgress? }
 * @returns {Promise<{ findings, checked, soft404 }>}
 */
export async function scanExposedFiles(baseUrl, http, opts = {}) {
  const paths = opts.paths || SENSITIVE_PATHS;
  const onProgress = opts.onProgress || (() => {});

  const { isSoft404, baseline } = await detectSoft404(baseUrl, http);

  const findings = [];
  let checked = 0;

  for (const entry of paths) {
    const url = new URL(entry.path, baseUrl).toString();
    // eslint-disable-next-line no-await-in-loop
    const res = await http.get(url);
    checked += 1;
    onProgress({ checked, total: paths.length, path: entry.path });
    if (!res.ok) continue;

    const exposed = isExposed(res, entry, isSoft404, baseline);
    if (exposed) {
      findings.push(
        makeFinding({
          type: entry.type,
          url,
          evidence: `${entry.desc} accessible (HTTP ${res.status})`,
          response: { statusCode: res.status, headers: res.headers, bodyExcerpt: (res.body || '').slice(0, 1000), responseTimeMs: res.timeMs },
        }),
      );
    }
  }

  return { findings, checked, soft404: isSoft404 };
}

/** Decide whether a path response indicates real exposure. */
export function isExposed(res, entry, isSoft404, baseline) {
  // 403 = exists but blocked — meaningful for admin panels (lower confidence,
  // but still a signal). We only treat 200 as exposure for files.
  if (res.status === 403) {
    return entry.type === 'exposed_admin_panel';
  }
  if (res.status !== 200) return false;

  // If the server soft-404s, a 200 alone means nothing — require the response
  // to differ from the soft-404 baseline.
  if (isSoft404 && baseline && looksSame(res, baseline)) return false;

  // Optional content match (e.g. /.git/HEAD must look like a git ref).
  if (entry.match && !entry.match.test(res.body || '')) return false;

  return true;
}
