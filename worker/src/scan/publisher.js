import { getRedis } from '../queue/connection.js';
import { progressChannel } from '@smartfuzz/shared/progress';

// SSE publisher — the worker publishes scan progress to a Redis pub/sub channel;
// the backend's SSE endpoint subscribes and forwards to the browser. A separate
// publisher connection (not the BullMQ one) keeps concerns clean.

let pub = null;
function publisher() {
  if (!pub) pub = getRedis().duplicate();
  return pub;
}

/** Publish a single SSE event for a scan. Best-effort (never throws). */
export function publishProgress(scanId, event) {
  try {
    publisher().publish(progressChannel(String(scanId)), JSON.stringify(event));
  } catch {
    /* best-effort: a dropped progress event must never fail the scan */
  }
}

export async function closePublisher() {
  if (pub) {
    await pub.quit().catch(() => pub.disconnect());
    pub = null;
  }
}
