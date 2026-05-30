import { describe, it, expect } from 'vitest';
import { loadConfig } from '../src/config.js';

// A minimal valid env baseline tests can spread and override.
const base = {
  NODE_ENV: 'test',
  JWT_SECRET: 'a-sufficiently-long-secret',
};

describe('loadConfig', () => {
  it('applies defaults for omitted values', () => {
    const cfg = loadConfig(base);
    expect(cfg.PORT).toBe(4000);
    expect(cfg.SCAN_RATE_LIMIT).toBe(10);
    expect(cfg.MAIL_TRANSPORT).toBe('ethereal');
    expect(cfg.AUTH_COOKIE_NAME).toBe('smartfuzz_token');
  });

  it('coerces numeric strings to numbers', () => {
    const cfg = loadConfig({ ...base, PORT: '8080', SCAN_MAX_DEPTH: '5' });
    expect(cfg.PORT).toBe(8080);
    expect(cfg.SCAN_MAX_DEPTH).toBe(5);
  });

  it('coerces string booleans for SCAN_ALLOW_PRIVATE', () => {
    expect(loadConfig({ ...base, SCAN_ALLOW_PRIVATE: 'true' }).SCAN_ALLOW_PRIVATE).toBe(true);
    expect(loadConfig({ ...base, SCAN_ALLOW_PRIVATE: '1' }).SCAN_ALLOW_PRIVATE).toBe(true);
    expect(loadConfig({ ...base, SCAN_ALLOW_PRIVATE: 'false' }).SCAN_ALLOW_PRIVATE).toBe(false);
    expect(loadConfig({ ...base, SCAN_ALLOW_PRIVATE: 'no' }).SCAN_ALLOW_PRIVATE).toBe(false);
    expect(loadConfig(base).SCAN_ALLOW_PRIVATE).toBe(false); // default off
  });

  it('rejects an invalid NODE_ENV', () => {
    expect(() => loadConfig({ ...base, NODE_ENV: 'staging' })).toThrow(/Invalid environment/);
  });

  it('rejects a too-short JWT secret', () => {
    expect(() => loadConfig({ ...base, JWT_SECRET: 'short' })).toThrow(/Invalid environment/);
  });

  it('rejects a non-URL FRONTEND_ORIGIN', () => {
    expect(() => loadConfig({ ...base, FRONTEND_ORIGIN: 'not-a-url' })).toThrow(/Invalid environment/);
  });

  it('rejects an invalid MAIL_TRANSPORT', () => {
    expect(() => loadConfig({ ...base, MAIL_TRANSPORT: 'sendgrid' })).toThrow(/Invalid environment/);
  });

  it('returns a frozen object', () => {
    const cfg = loadConfig(base);
    expect(Object.isFrozen(cfg)).toBe(true);
  });
});
