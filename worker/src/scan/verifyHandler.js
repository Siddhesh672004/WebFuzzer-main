import { Vulnerability } from '@smartfuzz/shared/models';
import { JOBS } from '@smartfuzz/shared/queues';
import { SSE_EVENTS } from '@smartfuzz/shared/progress';
import { HttpClient } from '../engine/httpClient.js';
import { RateLimiter } from '../safety/rateLimiter.js';
import { analyzeResponse } from '../engine/responseAnalyzer.js';
import { classifyParam } from '../engine/paramClassifier.js';
import { childLogger } from '../logger.js';

// Verify-fix handler (Phase 6). Re-fires a single finding's exact payload against
// its original endpoint and decides whether the vulnerability is now fixed.
// Runs on the REPORT queue (dispatches by job name) so we don't add a queue.
//
// Verdict:
//   • detector fires again, or original evidence marker still present → verified_persists
//   • neither → verified_fixed
//
// `http` and `models` are injectable for tests (no live network / DB needed).

const log = childLogger('verify');

/**
 * Re-fire one payload at one endpoint param and return the raw response.
 */
async function refire(http, { url, method = 'GET', param, payload }) {
  const target = new URL(url);
  if (method === 'GET' || !method) {
    target.searchParams.set(param, payload);
    return http.request({ url: target.toString(), method: 'GET' });
  }
  const data = `${encodeURIComponent(param)}=${encodeURIComponent(payload)}`;
  return http.request({
    url,
    method,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    data,
  });
}

/**
 * Decide if a finding still reproduces.
 * @returns {'verified_fixed'|'verified_persists'}
 */
export async function verifyFinding(http, vuln) {
  const { type, url, param, payload, evidence } = vuln;
  if (!url || !payload) return 'verified_fixed'; // nothing to re-fire → assume fixed

  const res = await refire(http, { url, method: vuln.request?.method, param, payload });
  const body = res.body || '';

  // 1) Re-run the single-response detector for this type.
  const baseline = { status: res.status, bodyLength: body.length, responseTimeMs: res.timeMs };
  const result = analyzeResponse(
    baseline,
    { status: res.status, headers: res.headers || {}, body, responseTimeMs: res.timeMs, finalUrl: url },
    { attackType: type, value: payload, url, param },
  );
  if (result?.finding) return 'verified_persists';

  // 2) Fallback marker check: if the distinctive part of the original evidence
  //    still appears verbatim in the response, treat as persisting. We use the
  //    raw payload reflected unencoded as the strongest signal.
  if (payload.length >= 4 && body.includes(payload)) return 'verified_persists';
  const marker = distinctiveMarker(evidence);
  if (marker && body.includes(marker)) return 'verified_persists';

  return 'verified_fixed';
}

// Pull a short distinctive token from the stored evidence string (e.g. a DB
// error fragment) to use as a cheap persistence signal.
function distinctiveMarker(evidence) {
  if (!evidence || typeof evidence !== 'string') return null;
  const m = evidence.match(/root:x:0:0|uid=\d+\([^)]+\)|SQL syntax|MongoError|LDAPException/i);
  return m ? m[0] : null;
}

/**
 * Build the REPORT-queue handler. Dispatches verify-fix jobs; report jobs are a
 * best-effort no-op (reports are generated on demand by the backend).
 */
export function buildVerifyHandler(deps = {}) {
  const publish = deps.publish || (() => {});
  const models = deps.models || { Vulnerability };

  return async (job) => {
    if (job.name !== JOBS.VERIFY_FIX) {
      // GENERATE_REPORT and others: nothing to do here (on-demand generation).
      return { status: 'noop', name: job.name };
    }

    const { scanId, vulnId } = job.data;
    let vuln = job.data.vuln;
    if (!vuln && vulnId) {
      vuln = await models.Vulnerability.findById(vulnId).lean().catch(() => null);
    }
    if (!vuln) {
      log.warn({ vulnId }, 'verify-fix: vulnerability not found');
      return { status: 'not_found', vulnId };
    }

    const http = deps.http ||
      new HttpClient({ rateLimiter: new RateLimiter(deps.rateLimit || 5), allowPrivate: deps.allowPrivate });

    let status;
    try {
      status = await verifyFinding(http, vuln);
    } catch (err) {
      log.warn({ err: err.message, vulnId }, 'verify-fix failed');
      status = 'unverified';
    }

    if (status === 'verified_fixed' || status === 'verified_persists') {
      await models.Vulnerability.updateOne(
        { _id: vulnId },
        {
          $set: {
            verificationStatus: status,
            verifiedAt: new Date(),
            ...(status === 'verified_fixed' ? { isFixed: true } : {}),
          },
        },
      ).catch((err) => log.warn({ err: err.message, vulnId }, 'failed to persist verify status'));
    }

    publish(scanId, { kind: SSE_EVENTS.VERIFY, data: { vulnId, status } });
    return { status, vulnId };
  };
}
