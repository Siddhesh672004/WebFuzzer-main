import { describe, it, expect } from 'vitest';
import {
  QUEUES,
  QUEUE_NAMES,
  MODULE_QUEUES,
  JOBS,
  PRIORITY,
  scanQueuePrefix,
} from '../src/queues.js';

describe('queue constants', () => {
  it('defines the six module queues plus orchestration, report, and js-secret', () => {
    expect(QUEUE_NAMES).toHaveLength(9);
    expect(QUEUE_NAMES).toContain('crawl-queue');
    expect(QUEUE_NAMES).toContain('report-queue');
    expect(QUEUE_NAMES).toContain('js-secret-queue');
  });

  it('MODULE_QUEUES is exactly the six scanning modules', () => {
    expect(MODULE_QUEUES).toHaveLength(6);
    expect(MODULE_QUEUES).toEqual([
      QUEUES.CRAWL,
      QUEUES.PASSIVE,
      QUEUES.EXPOSED,
      QUEUES.FUZZ,
      QUEUES.AUTH,
      QUEUES.TECH,
    ]);
  });

  it('has no duplicate queue names', () => {
    expect(new Set(QUEUE_NAMES).size).toBe(QUEUE_NAMES.length);
  });

  it('exposes job names and is frozen', () => {
    expect(JOBS.START_SCAN).toBe('start-scan');
    expect(Object.isFrozen(QUEUES)).toBe(true);
    expect(Object.isFrozen(JOBS)).toBe(true);
  });

  it('orders priorities so mutations outrank normal payloads', () => {
    expect(PRIORITY.MUTATION).toBeLessThan(PRIORITY.NORMAL);
    expect(PRIORITY.NORMAL).toBeLessThan(PRIORITY.LOW);
  });

  it('namespaces a scan queue prefix by id', () => {
    expect(scanQueuePrefix('abc123')).toBe('sf:abc123');
  });
});
