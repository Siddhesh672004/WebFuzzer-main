import { Scan, Endpoint, Vulnerability } from '@smartfuzz/shared/models';
import { SSE_EVENTS } from '@smartfuzz/shared/progress';
import { RateLimiter } from '../safety/rateLimiter.js';
import { HttpClient } from '../engine/httpClient.js';
import { buildAuthHeaders } from '../engine/authContext.js';
import { childLogger } from '../logger.js';

// Per-scan shared context for the fan-out path. The core invariant is that
// all Phase-2 modules of a scan share ONE rate limiter and ONE HttpClient so
// concurrent modules can't collectively exceed the target's rate budget. In the
// monolithic ScanRunner that's trivial (one object). Across fan-out jobs we
// preserve it by caching the context per scanId within the worker process — all
// module queues are registered in the same process, so jobs for one scan reuse
// the same limiter+client.
//
// Finding persistence (dedup-by-signature upsert + SSE emit + running counts)
// lives here so every module records findings identically.

const log = childLogger('scanContext');

const contexts = new Map(); // scanId → ScanContext

export class ScanContext {
  constructor({ scanId, targetUrl, config = {}, publish = () => {}, models, http }) {
    this.scanId = scanId;
    this.targetUrl = targetUrl;
    this.cfg = config;
    this.publish = publish;
    this.models = models || { Scan, Endpoint, Vulnerability };

    const limiter = new RateLimiter(config.rateLimit || 10);
    this.http = http || new HttpClient({
      rateLimiter: limiter,
      allowPrivate: config.allowPrivate,
      defaultHeaders: buildAuthHeaders(config.auth || {}),
    });

    this.counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
    this.vulnCount = 0;
    this.endpointCount = 0;
  }

  emit(kind, data) {
    this.publish(this.scanId, { kind, data });
  }

  setModule(module, status, summary) {
    this.emit(SSE_EVENTS.MODULE, { module, status, ...(summary ? { summary } : {}) });
  }

  /** Persist findings (deduped by signature within the scan) + emit SSE. */
  async saveFindings(findings) {
    for (const f of findings) {
      try {
        // eslint-disable-next-line no-await-in-loop
        const res = await this.models.Vulnerability.updateOne(
          { scanId: this.scanId, signature: f.signature },
          { $setOnInsert: { ...f, scanId: this.scanId } },
          { upsert: true },
        );
        if (res.upsertedCount > 0) {
          this.vulnCount += 1;
          this.counts[f.severity] = (this.counts[f.severity] || 0) + 1;
          this.emit(SSE_EVENTS.FINDING, {
            type: f.type, severity: f.severity, cvssScore: f.cvssScore, url: f.url, param: f.param,
          });
        }
      } catch (err) {
        log.warn({ err: err.message, sig: f.signature }, 'failed to save finding');
      }
    }
  }
}

/** Get or create the cached context for a scan. */
export function getScanContext(opts) {
  const { scanId } = opts;
  if (contexts.has(scanId)) return contexts.get(scanId);
  const ctx = new ScanContext(opts);
  contexts.set(scanId, ctx);
  return ctx;
}

/** Drop a scan's cached context (called when the scan finalizes). */
export function releaseScanContext(scanId) {
  contexts.delete(scanId);
}

/** Test/visibility helper. */
export function activeContextCount() {
  return contexts.size;
}
