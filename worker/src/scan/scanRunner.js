import { Scan, Endpoint, Vulnerability } from '@smartfuzz/shared/models';
import { progressChannel, SSE_EVENTS } from '@smartfuzz/shared/progress';
import { RateLimiter } from '../safety/rateLimiter.js';
import { HttpClient } from '../engine/httpClient.js';
import { crawl } from '../engine/crawler.js';
import { analyzePassive } from '../engine/passiveAnalyzer.js';
import { scanExposedFiles } from '../engine/exposedFiles.js';
import { fingerprint } from '../engine/techFingerprinter.js';
import { fuzzEndpoint } from '../engine/payloadFuzzer.js';
import { testAuth } from '../engine/authTester.js';
import { scanJsSecrets } from '../engine/jsSecretScanner.js';
import { makeFinding } from '../engine/findingFactory.js';
import { childLogger } from '../logger.js';

// Scan runner — the orchestrator that turns a queued scan into findings. Fans
// out the Phase-2 modules, all sharing ONE rate limiter so concurrent modules
// can't DoS the target. Persists endpoints + deduped vulnerabilities, updates
// scan progress/stats, and publishes SSE events via an injected publisher.
//
// Dependencies (http, publisher, models) are injectable so the whole runner is
// testable without Redis/network. The fuzzer + auth tester (Phase 3) plug in
// here later via the same pattern.

const log = childLogger('scanRunner');

// Module weights for the overall progress percentage. pct() normalizes by the
// sum of active-module weights, so these need not total 100.
const MODULE_WEIGHT = { crawler: 25, passive: 15, exposed: 20, tech: 15, fuzzer: 20, auth: 5, jsSecrets: 10 };

export class ScanRunner {
  /**
   * @param {object} deps
   *   scanId, targetUrl
   *   http?        HttpClient (injectable)
   *   publish?     (scanId, event) => void   SSE publisher
   *   config?      { maxDepth, maxEndpoints, rateLimit, allowPrivate }
   *   models?      { Scan, Endpoint, Vulnerability }
   *   modules?     subset of ['crawler','passive','exposed','tech'] to run
   */
  constructor(deps) {
    this.scanId = deps.scanId;
    this.targetUrl = deps.targetUrl;
    this.cfg = deps.config || {};
    this.models = deps.models || { Scan, Endpoint, Vulnerability };
    this.publish = deps.publish || (() => {});
    this.modules = deps.modules || ['crawler', 'passive', 'exposed', 'tech', 'fuzzer', 'auth', 'jsSecrets'];

    const limiter = new RateLimiter(this.cfg.rateLimit || 10);
    this.http =
      deps.http ||
      new HttpClient({ rateLimiter: limiter, allowPrivate: this.cfg.allowPrivate });

    this.progress = { crawler: 0, passive: 0, exposed: 0, tech: 0, fuzzer: 0, auth: 0, jsSecrets: 0 };
    this.counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
    this.endpointCount = 0;
    this.vulnCount = 0;
    this.jsUrls = [];
  }

  emit(kind, data) {
    this.publish(this.scanId, { kind, data });
  }

  setModule(module, status) {
    this.emit(SSE_EVENTS.MODULE, { module, status });
  }

  pct() {
    let total = 0;
    for (const m of this.modules) total += (this.progress[m] || 0) * (MODULE_WEIGHT[m] || 0) / 100;
    const possible = this.modules.reduce((s, m) => s + (MODULE_WEIGHT[m] || 0), 0) || 1;
    return Math.min(100, Math.round((total / possible) * 100));
  }

  async pushProgress(currentModule) {
    const percentComplete = this.pct();
    await this.models.Scan.updateOne(
      { _id: this.scanId },
      {
        $set: {
          'progress.percentComplete': percentComplete,
          'progress.currentModule': currentModule,
          'progress.endpointsDiscovered': this.endpointCount,
          'progress.vulnerabilitiesFound': this.vulnCount,
        },
      },
    ).catch(() => {});
    this.emit(SSE_EVENTS.PROGRESS, {
      percentComplete,
      currentModule,
      endpointsDiscovered: this.endpointCount,
      vulnerabilitiesFound: this.vulnCount,
      counts: { ...this.counts },
    });
  }

  /** Persist a batch of findings (deduped by signature within the scan). */
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
          this.emit(SSE_EVENTS.FINDING, { type: f.type, severity: f.severity, cvssScore: f.cvssScore, url: f.url, param: f.param });
        }
      } catch (err) {
        log.warn({ err: err.message, sig: f.signature }, 'failed to save finding');
      }
    }
  }

  // ── Module runners ──

  async runCrawler() {
    this.setModule('crawler', 'running');
    const result = await crawl(this.targetUrl, this.http, {
      maxDepth: this.cfg.maxDepth ?? 3,
      maxEndpoints: this.cfg.maxEndpoints ?? 500,
      onProgress: ({ endpointsDiscovered }) => {
        this.endpointCount = endpointsDiscovered;
        this.progress.crawler = Math.min(90, endpointsDiscovered);
      },
    });
    // Persist endpoints.
    for (const e of result.endpoints) {
      // eslint-disable-next-line no-await-in-loop
      await this.models.Endpoint.updateOne(
        { scanId: this.scanId, url: e.url, method: e.method },
        { $setOnInsert: { ...e, scanId: this.scanId } },
        { upsert: true },
      ).catch(() => {});
    }
    this.endpointCount = result.endpoints.length;
    // JS file URLs (<script src>) collected for the JS Secret Scanner.
    this.jsUrls = result.jsUrls || [];
    this.progress.crawler = 100;
    this.setModule('crawler', 'completed');
    await this.pushProgress('crawler');
    return result.endpoints;
  }

  async runPassive() {
    this.setModule('passive', 'running');
    const res = await this.http.get(this.targetUrl);
    if (res.ok) {
      const findings = analyzePassive({ url: res.finalUrl || this.targetUrl, status: res.status, headers: res.headers, body: res.body, responseTimeMs: res.timeMs });
      await this.saveFindings(findings);
    }
    this.progress.passive = 100;
    this.setModule('passive', res.ok ? 'completed' : 'degraded');
    await this.pushProgress('passive');
  }

  async runExposed() {
    this.setModule('exposed', 'running');
    const { findings } = await scanExposedFiles(this.targetUrl, this.http, {
      onProgress: ({ checked, total }) => {
        this.progress.exposed = Math.round((checked / total) * 100);
      },
    });
    await this.saveFindings(findings);
    this.progress.exposed = 100;
    this.setModule('exposed', 'completed');
    await this.pushProgress('exposed');
  }

  async runTech() {
    this.setModule('tech', 'running');
    const res = await this.http.get(this.targetUrl);
    if (res.ok) {
      const { findings } = fingerprint({ url: res.finalUrl || this.targetUrl, headers: res.headers, body: res.body });
      await this.saveFindings(findings);
    }
    this.progress.tech = 100;
    this.setModule('tech', res.ok ? 'completed' : 'degraded');
    await this.pushProgress('tech');
  }

  async runFuzzer(endpoints = []) {
    this.setModule('fuzzer', 'running');
    let totalPayloadsSent = 0;
    const endpointsToFuzz = endpoints.length > 0 ? endpoints : [];

    for (let i = 0; i < endpointsToFuzz.length; i++) {
      const endpoint = endpointsToFuzz[i];
      try {
        // eslint-disable-next-line no-await-in-loop
        const { findings, payloadsSent } = await fuzzEndpoint(endpoint, this.http, {
          maxPayloads: 50,
          onFinding: (f) => this.saveFindings([f]),
          onProgress: () => {
            totalPayloadsSent += 1;
            this.progress.fuzzer = Math.round(((i + 1) / endpointsToFuzz.length) * 100);
          },
        });
        totalPayloadsSent += payloadsSent;
        await this.saveFindings(findings);
      } catch (err) {
        log.warn({ err: err.message, url: endpoint.url }, 'fuzz endpoint failed');
      }
    }

    await this.models.Scan.updateOne(
      { _id: this.scanId },
      { $set: { 'progress.payloadsSent': totalPayloadsSent } },
    ).catch(() => {});

    this.progress.fuzzer = 100;
    this.setModule('fuzzer', 'completed');
    await this.pushProgress('fuzzer');
  }

  async runAuth() {
    this.setModule('auth', 'running');
    try {
      const { findings } = await testAuth(this.targetUrl, this.http);
      await this.saveFindings(findings);
    } catch (err) {
      log.warn({ err: err.message }, 'auth tester failed');
    }
    this.progress.auth = 100;
    this.setModule('auth', 'completed');
    await this.pushProgress('auth');
  }

  async runJsSecrets() {
    this.setModule('jsSecrets', 'running');
    const urls = this.jsUrls || [];
    if (urls.length === 0) {
      // Nothing to scan — complete cleanly with a no-op summary.
      this.progress.jsSecrets = 100;
      this.setModule('jsSecrets', 'completed');
      await this.pushProgress('jsSecrets');
      return;
    }
    try {
      const raw = await scanJsSecrets({
        urls,
        http: this.http,
        scanId: this.scanId,
        publish: this.publish,
      });
      // Normalize each secret finding through the shared factory (severity +
      // CVSS from the subtype), then re-attach the secret-specific metadata that
      // makeFinding doesn't carry. The secret type is used as the signature
      // `param` so distinct secrets in the SAME file get distinct signatures
      // (otherwise they'd collide and dedupe to one) while staying stable across
      // rescans for the comparison engine.
      const findings = raw.map((r) => ({
        ...makeFinding({
          type: r.type,
          subtype: r.subtype,
          url: r.jsFileUrl,
          param: r.secretType,
          evidence: r.evidence,
        }),
        secretType: r.secretType,
        jsFileUrl: r.jsFileUrl,
        lineNumber: r.lineNumber,
        matchPreview: r.matchPreview,
      }));
      await this.saveFindings(findings);
    } catch (err) {
      log.warn({ err: err.message }, 'js secret scanner failed');
    }
    this.progress.jsSecrets = 100;
    this.setModule('jsSecrets', 'completed');
    await this.pushProgress('jsSecrets');
  }

  /** Run the full scan. Returns a summary. */
  async run() {
    this.emit(SSE_EVENTS.STATUS, { status: 'running' });
    await this.models.Scan.updateOne({ _id: this.scanId }, { $set: { status: 'running', 'stats.startTime': new Date() } }).catch(() => {});

    // Crawler runs first — its output feeds the fuzzer.
    let crawledEndpoints = [];
    if (this.modules.includes('crawler')) {
      crawledEndpoints = await this.runCrawler().catch((err) => {
        log.error({ err: err.message }, 'crawler failed');
        return [];
      });
    }

    // All other modules run concurrently after the crawler.
    const concurrentRunners = [];
    if (this.modules.includes('passive')) concurrentRunners.push(() => this.runPassive());
    if (this.modules.includes('exposed')) concurrentRunners.push(() => this.runExposed());
    if (this.modules.includes('tech')) concurrentRunners.push(() => this.runTech());
    if (this.modules.includes('fuzzer')) concurrentRunners.push(() => this.runFuzzer(crawledEndpoints));
    if (this.modules.includes('auth')) concurrentRunners.push(() => this.runAuth());
    if (this.modules.includes('jsSecrets')) concurrentRunners.push(() => this.runJsSecrets());

    const results = await Promise.allSettled(concurrentRunners.map((fn) => fn()));
    results.filter((r) => r.status === 'rejected').forEach((r) => log.error({ err: r.reason?.message }, 'module failed'));

    const status = 'completed';
    const endTime = new Date();
    await this.models.Scan.updateOne(
      { _id: this.scanId },
      {
        $set: {
          status,
          'progress.percentComplete': 100,
          'stats.endTime': endTime,
          'stats.totalEndpoints': this.endpointCount,
          'stats.totalVulnerabilities': this.vulnCount,
          'stats.critical': this.counts.critical || 0,
          'stats.high': this.counts.high || 0,
          'stats.medium': this.counts.medium || 0,
          'stats.low': this.counts.low || 0,
          'stats.informational': this.counts.informational || 0,
          'stats.securityScore': Math.max(0, 100
            - (this.counts.critical || 0) * 20
            - (this.counts.high || 0) * 10
            - (this.counts.medium || 0) * 5
            - (this.counts.low || 0) * 2),
        },
      },
    ).catch(() => {});

    this.emit(SSE_EVENTS.STATUS, { status });
    this.emit(SSE_EVENTS.DONE, { status });

    return { status, endpoints: this.endpointCount, vulnerabilities: this.vulnCount, counts: this.counts };
  }
}
