import { describe, it, expect } from 'vitest';
import { RateLimiter } from '../src/safety/rateLimiter.js';

// Use an injectable clock so timing tests are deterministic (no real waits).
function fakeClock(start = 0) {
  let t = start;
  return { now: () => t, advance: (ms) => { t += ms; } };
}

describe('RateLimiter', () => {
  it('allows up to capacity immediately (burst)', () => {
    const clk = fakeClock();
    const rl = new RateLimiter(10, 10, clk.now);
    let allowed = 0;
    for (let i = 0; i < 15; i += 1) if (rl.tryTake()) allowed += 1;
    expect(allowed).toBe(10); // burst capacity
  });

  it('refills tokens over time at the configured rate', () => {
    const clk = fakeClock();
    const rl = new RateLimiter(10, 10, clk.now);
    for (let i = 0; i < 10; i += 1) rl.tryTake(); // drain
    expect(rl.tryTake()).toBe(false);
    clk.advance(500); // 0.5s → +5 tokens at 10/s
    let allowed = 0;
    for (let i = 0; i < 10; i += 1) if (rl.tryTake()) allowed += 1;
    expect(allowed).toBe(5);
  });

  it('reports ms until the next token', () => {
    const clk = fakeClock();
    const rl = new RateLimiter(10, 1, clk.now); // capacity 1
    expect(rl.tryTake()).toBe(true);
    expect(rl.tryTake()).toBe(false);
    // at 10/s, next token in ~100ms
    expect(rl.msUntilNext()).toBeGreaterThan(0);
    expect(rl.msUntilNext()).toBeLessThanOrEqual(100);
  });

  it('never exceeds capacity when idle', () => {
    const clk = fakeClock();
    const rl = new RateLimiter(10, 10, clk.now);
    clk.advance(100_000); // long idle
    let allowed = 0;
    for (let i = 0; i < 50; i += 1) if (rl.tryTake()) allowed += 1;
    expect(allowed).toBe(10); // capped at capacity, not unbounded
  });

  it('rejects a non-positive rate', () => {
    expect(() => new RateLimiter(0)).toThrow();
  });

  it('take() resolves once a token is available (real timers)', async () => {
    const rl = new RateLimiter(50); // fast for test speed
    await rl.take();
    await rl.take();
    expect(true).toBe(true); // resolved without hanging
  });
});
