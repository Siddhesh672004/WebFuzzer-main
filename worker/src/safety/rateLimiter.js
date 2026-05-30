// Shared outbound rate limiter (IMPLEMENTATION_PLAN §10.2). A token-bucket that
// every module's HTTP request passes through, so "6 modules firing at once"
// can't become a 60 req/s DoS. Default 10 req/s, configurable per scan.
//
// take() resolves when a token is available, smoothing bursts to the configured
// rate. Tokens refill continuously based on elapsed time.

export class RateLimiter {
  /**
   * @param {number} ratePerSec sustained requests/second
   * @param {number} [burst] max tokens in the bucket (defaults to ratePerSec)
   * @param {() => number} [now] injectable clock for tests (ms)
   */
  constructor(ratePerSec, burst = ratePerSec, now = () => Date.now()) {
    if (ratePerSec <= 0) throw new Error('ratePerSec must be > 0');
    this.rate = ratePerSec;
    this.capacity = Math.max(1, burst);
    this.tokens = this.capacity;
    this.now = now;
    this.last = now();
  }

  #refill() {
    const t = this.now();
    const elapsedSec = (t - this.last) / 1000;
    if (elapsedSec > 0) {
      this.tokens = Math.min(this.capacity, this.tokens + elapsedSec * this.rate);
      this.last = t;
    }
  }

  /** Try to consume a token without waiting. Returns true if one was available. */
  tryTake() {
    this.#refill();
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return true;
    }
    return false;
  }

  /** ms until the next token is available (0 if available now). */
  msUntilNext() {
    this.#refill();
    if (this.tokens >= 1) return 0;
    return Math.ceil(((1 - this.tokens) / this.rate) * 1000);
  }

  /** Acquire a token, waiting if necessary. Resolves when granted. */
  async take() {
    // Loop because between scheduling and waking, another caller may take it.
    // eslint-disable-next-line no-constant-condition
    while (true) {
      if (this.tryTake()) return;
      const wait = this.msUntilNext();
      // eslint-disable-next-line no-await-in-loop
      await delay(wait > 0 ? wait : 1);
    }
  }
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// One limiter per scan id, so concurrent scans don't share a budget.
const perScan = new Map();

export function getRateLimiter(scanId, ratePerSec) {
  if (!perScan.has(scanId)) perScan.set(scanId, new RateLimiter(ratePerSec));
  return perScan.get(scanId);
}

export function disposeRateLimiter(scanId) {
  perScan.delete(scanId);
}
