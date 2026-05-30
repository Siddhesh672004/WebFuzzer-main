import { describe, it, expect } from 'vitest';
import { redisOptions } from '../src/queue/connection.js';

// We can't open a real Redis in unit tests, but we CAN assert the connection
// options are shaped correctly — in particular that maxRetriesPerRequest is
// null, which BullMQ requires or it throws at worker startup.

describe('redisOptions', () => {
  it('sets maxRetriesPerRequest to null (BullMQ requirement)', () => {
    expect(redisOptions().maxRetriesPerRequest).toBeNull();
  });

  it('includes host and port from config defaults', () => {
    const opts = redisOptions();
    expect(opts.host).toBe('localhost');
    expect(opts.port).toBe(6379);
  });

  it('omits password when none is configured', () => {
    // default config has no REDIS_PASSWORD
    expect(redisOptions().password).toBeUndefined();
  });

  it('enables the ready check', () => {
    expect(redisOptions().enableReadyCheck).toBe(true);
  });
});
