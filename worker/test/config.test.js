import { describe, it, expect } from 'vitest';
import { loadConfig } from '../src/config.js';

const base = { NODE_ENV: 'test' };

describe('worker loadConfig', () => {
  it('applies scan-safety defaults', () => {
    const cfg = loadConfig(base);
    expect(cfg.SCAN_RATE_LIMIT).toBe(10);
    expect(cfg.SCAN_MAX_DEPTH).toBe(3);
    expect(cfg.SCAN_MAX_ENDPOINTS).toBe(500);
    expect(cfg.SCAN_ALLOW_PRIVATE).toBe(false);
    expect(cfg.WORKER_FUZZ_CONCURRENCY).toBe(5);
  });

  it('coerces numeric env strings', () => {
    const cfg = loadConfig({ ...base, SCAN_RATE_LIMIT: '25', WORKER_FUZZ_CONCURRENCY: '8' });
    expect(cfg.SCAN_RATE_LIMIT).toBe(25);
    expect(cfg.WORKER_FUZZ_CONCURRENCY).toBe(8);
  });

  it('coerces SCAN_ALLOW_PRIVATE booleans', () => {
    expect(loadConfig({ ...base, SCAN_ALLOW_PRIVATE: 'true' }).SCAN_ALLOW_PRIVATE).toBe(true);
    expect(loadConfig({ ...base, SCAN_ALLOW_PRIVATE: 'false' }).SCAN_ALLOW_PRIVATE).toBe(false);
  });

  it('rejects a non-positive rate limit', () => {
    expect(() => loadConfig({ ...base, SCAN_RATE_LIMIT: '0' })).toThrow(/Invalid worker environment/);
    expect(() => loadConfig({ ...base, SCAN_RATE_LIMIT: '-5' })).toThrow(/Invalid worker environment/);
  });

  it('rejects an invalid LOG_LEVEL', () => {
    expect(() => loadConfig({ ...base, LOG_LEVEL: 'verbose' })).toThrow(/Invalid worker environment/);
  });

  it('returns a frozen object', () => {
    expect(Object.isFrozen(loadConfig(base))).toBe(true);
  });
});
