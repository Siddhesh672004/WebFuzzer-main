import axios from 'axios';
import { config } from '../config.js';
import { assertSafeUrl } from '../safety/urlGuard.js';

// Shared HTTP client for the scan engine. Every outbound request is validated by
// urlGuard FIRST (SSRF defense, re-checked on each redirect hop we follow
// manually), capped in body size, and time-bounded. Modules inject a rate
// limiter so all traffic is smoothed to the configured rate.

const MAX_REDIRECTS = 5;

export class HttpClient {
  /**
   * @param {object} opts
   *   rateLimiter? { take(): Promise<void> }
   *   allowPrivate? boolean
   *   timeoutMs?, maxBodyBytes?
   *   onActivity? (info: { method, url, hop }) => void   live activity hook (never throws)
   *   defaultHeaders? object   headers merged into every request (e.g. auth Cookie / custom headers
   *                            for an authenticated crawl); per-request headers still win.
   *   axiosInstance? (injectable for tests)
   */
  constructor(opts = {}) {
    this.rateLimiter = opts.rateLimiter || null;
    this.allowPrivate = opts.allowPrivate ?? config.SCAN_ALLOW_PRIVATE;
    this.timeoutMs = opts.timeoutMs ?? config.SCAN_REQUEST_TIMEOUT_MS;
    this.maxBodyBytes = opts.maxBodyBytes ?? config.SCAN_MAX_BODY_BYTES;
    this.onActivity = opts.onActivity || null;
    this.defaultHeaders = opts.defaultHeaders || {};
    this.axios = opts.axiosInstance || axios.create();
  }

  /** Merge additional default headers (e.g. session cookies captured after a form login). */
  setDefaultHeaders(headers = {}) {
    this.defaultHeaders = { ...this.defaultHeaders, ...headers };
  }

  /**
   * Perform a guarded request. Follows redirects manually so urlGuard runs on
   * every hop. Returns { status, headers, body, timeMs, finalUrl, truncated }.
   */
  async request({ url, method = 'GET', headers = {}, data = undefined, hop = 0 }) {
    await assertSafeUrl(url, { allowPrivate: this.allowPrivate });
    if (this.rateLimiter) await this.rateLimiter.take();

    // Live activity hook — fires once per guarded request (incl. each redirect
    // hop). Guarded so a misbehaving listener can never break a scan.
    if (this.onActivity) {
      try {
        this.onActivity({ method, url, hop });
      } catch {
        /* never let activity reporting affect the request */
      }
    }

    const start = Date.now();
    let res;
    try {
      res = await this.axios.request({
        url,
        method,
        headers: { 'User-Agent': 'SmartFuzz/0.1 (+security-scanner)', ...this.defaultHeaders, ...headers },
        data,
        timeout: this.timeoutMs,
        maxRedirects: 0, // we handle redirects ourselves (re-guard each hop)
        responseType: 'text',
        transformResponse: (x) => x, // keep raw body
        validateStatus: () => true, // never throw on status; we inspect it
        maxContentLength: this.maxBodyBytes,
        maxBodyLength: this.maxBodyBytes,
      });
    } catch (err) {
      const timeMs = Date.now() - start;
      // Network-level failures are returned as a structured error, not thrown,
      // so a single bad endpoint doesn't kill a scan.
      return {
        ok: false,
        error: err.code || err.message,
        status: 0,
        headers: {},
        body: '',
        timeMs,
        finalUrl: url,
      };
    }

    const timeMs = Date.now() - start;
    const status = res.status;

    // Manual redirect handling with per-hop guard.
    if (status >= 300 && status < 400 && res.headers.location && hop < MAX_REDIRECTS) {
      const nextUrl = new URL(res.headers.location, url).toString();
      return this.request({ url: nextUrl, method, headers, hop: hop + 1 });
    }

    let body = typeof res.data === 'string' ? res.data : String(res.data ?? '');
    let truncated = false;
    if (body.length > this.maxBodyBytes) {
      body = body.slice(0, this.maxBodyBytes);
      truncated = true;
    }

    return {
      ok: true,
      status,
      headers: res.headers,
      body,
      timeMs,
      finalUrl: url,
      truncated,
      redirects: hop,
    };
  }

  get(url, headers) {
    return this.request({ url, method: 'GET', headers });
  }
}
