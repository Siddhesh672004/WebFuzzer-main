// BullMQ queue + job name constants. Shared because the backend ENQUEUES jobs
// and the worker CONSUMES them — both must agree on the exact names or jobs
// silently never run. Single source of truth prevents that class of bug.

// The six scanning modules each get their own queue (PRD §9.1 — "all six fire
// simultaneously"). A shared rate limiter (not separate queues) is what keeps
// concurrency safe; see worker/src/safety/rateLimiter.js.
export const QUEUES = Object.freeze({
  CRAWL: 'crawl-queue',
  PASSIVE: 'passive-queue',
  EXPOSED: 'exposed-queue',
  FUZZ: 'fuzz-queue',
  AUTH: 'auth-queue',
  TECH: 'tech-queue',
  // Orchestration: fan-out on scan start, aggregate/report on completion.
  ORCHESTRATE: 'orchestrate-queue',
  REPORT: 'report-queue',
  // Reserved for the JS Secret Scanner. Detection currently runs inside
  // ScanRunner (Phase 2), so this queue has no registered worker yet — it exists
  // for forward-compatible fan-out, mirroring the dormant module queues above.
  JS_SECRET: 'js-secret-queue',
});

// Frozen list for iteration (e.g. registering all workers).
export const QUEUE_NAMES = Object.freeze(Object.values(QUEUES));

// The six module queues that fan out from a scan start.
export const MODULE_QUEUES = Object.freeze([
  QUEUES.CRAWL,
  QUEUES.PASSIVE,
  QUEUES.EXPOSED,
  QUEUES.FUZZ,
  QUEUES.AUTH,
  QUEUES.TECH,
]);

// Job names within queues (used for typed handlers and logging).
export const JOBS = Object.freeze({
  START_SCAN: 'start-scan',
  CRAWL_TARGET: 'crawl-target',
  PASSIVE_ANALYZE: 'passive-analyze',
  SCAN_EXPOSED: 'scan-exposed',
  FUZZ_ENDPOINT: 'fuzz-endpoint',
  FUZZ_MUTATION: 'fuzz-mutation',
  AUTH_TEST: 'auth-test',
  TECH_FINGERPRINT: 'tech-fingerprint',
  GENERATE_REPORT: 'generate-report',
  VERIFY_FIX: 'verify-fix',
  SCAN_JS_SECRETS: 'scan-js-secrets',
});

// BullMQ job priorities (lower number = higher priority). Mutations jump ahead
// of fresh payloads so a promising lead is chased before breadth (PRD §9.5e).
export const PRIORITY = Object.freeze({
  MUTATION: 1,
  NORMAL: 10,
  LOW: 20,
});

/** Namespaced queue prefix per scan, so concurrent scans stay isolated. */
export function scanQueuePrefix(scanId) {
  return `sf:${scanId}`;
}
