// Cross-process progress channel naming + event shapes for live scan updates.
// The worker publishes progress to a Redis pub/sub channel; the backend SSE
// endpoint subscribes and forwards to the browser. Shared so both ends agree.

/** Redis pub/sub channel for a scan's progress events. */
export function progressChannel(scanId) {
  return `scan:progress:${scanId}`;
}

// Event kinds streamed over SSE.
export const SSE_EVENTS = Object.freeze({
  PROGRESS: 'progress', // { percentComplete, currentModule, counts, moduleStatus }
  FINDING: 'finding', // a newly confirmed vulnerability (summary)
  MODULE: 'module', // { module, status }
  STATUS: 'status', // { status: running|completed|failed }
  ACTIVITY: 'activity', // { lines: [{ message, type }] } — batched + throttled live feed
  DONE: 'done', // terminal — stream can close
  VERIFY: 'verify_result', // { vulnId, status: verified_fixed|verified_persists }
});

/** Build a normalized progress event payload. */
export function progressEvent(kind, data) {
  return { kind, data, at: undefined };
}
