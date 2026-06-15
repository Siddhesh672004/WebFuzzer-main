import { config } from '../config.js';
import { childLogger } from '../logger.js';

// AI payload generation — optional, context-aware attack payloads to augment the
// deterministic curated/wordlist library. OFF by default (AI_PAYLOAD_MODE=off)
// so CI, grading, and offline use never depend on an external quota or network.
//
// Two backends, both called over plain HTTP (Node's global fetch) so we add NO
// SDK dependency:
//   • gemini — the free Google Gemini REST API (needs GEMINI_API_KEY)
//   • ollama — a local Ollama server (fully offline; needs no key)
//
// A circuit breaker trips on HTTP 429 and suppresses calls for a cooldown
// window, so a rate-limited free tier degrades to "curated payloads only"
// instead of stalling every fuzz. These infrastructure calls deliberately do
// NOT go through the scan HttpClient/urlGuard (that guard is for scan *targets*;
// Ollama at localhost would otherwise be blocked) — they're SmartFuzz's own
// service calls, like Mongo/Redis.

const log = childLogger('aiPayloads');

let circuitOpen = false;
let circuitOpenedAt = 0;

const PROMPT = (vulnType, paramName, paramContext) =>
  `You are a security researcher generating test payloads for AUTHORIZED penetration testing.
Target parameter: "${paramName}"
Context clues: ${paramContext || 'unknown'}
Vulnerability class: ${vulnType}
Generate exactly 5 targeted attack payloads for this specific parameter and class.
Respond ONLY with a JSON array of strings. No explanation, no markdown fences.
Example: ["payload1", "payload2", "payload3", "payload4", "payload5"]`;

/**
 * Generate AI payloads for a (vulnType, param) pair. Returns [] when disabled,
 * rate-limited, or on any error — never throws.
 * @param {string} vulnType
 * @param {string} paramName
 * @param {string} [paramContext]
 * @param {object} [overrides] test seam: { mode, cooldownMs }
 * @returns {Promise<string[]>}
 */
export async function generateAiPayloads(vulnType, paramName, paramContext = '', overrides = {}) {
  const mode = overrides.mode ?? config.AI_PAYLOAD_MODE;
  if (mode === 'off') return [];

  const cooldown = overrides.cooldownMs ?? config.AI_PAYLOAD_RATE_LIMIT_COOLDOWN_MS;
  if (circuitOpen) {
    if (Date.now() - circuitOpenedAt < cooldown) return [];
    circuitOpen = false; // cooldown elapsed — try again
  }

  try {
    const raw = mode === 'gemini'
      ? await callGemini(vulnType, paramName, paramContext, overrides)
      : await callOllama(vulnType, paramName, paramContext, overrides);
    return sanitize(raw);
  } catch (err) {
    if (isRateLimit(err)) {
      circuitOpen = true;
      circuitOpenedAt = Date.now();
      log.warn(`AI rate limited (429) — circuit breaker open for ${Math.round(cooldown / 1000)}s`);
    } else {
      log.warn({ err: err.message }, 'AI payload generation failed — using curated payloads only');
    }
    return [];
  }
}

function isRateLimit(err) {
  return err?.status === 429 || /\b429\b/.test(String(err?.message || ''));
}

function sanitize(values) {
  if (!Array.isArray(values)) return [];
  const cap = config.AI_PAYLOAD_MAX_PER_TYPE || 5;
  return values
    .filter((v) => typeof v === 'string' && v.length > 0 && v.length <= 2000)
    .slice(0, cap);
}

/** Tolerantly extract the first JSON array from a model response. */
export function parseJsonArray(text) {
  const cleaned = String(text).replace(/```json|```/g, '').trim();
  const start = cleaned.indexOf('[');
  const end = cleaned.lastIndexOf(']');
  const slice = start >= 0 && end > start ? cleaned.slice(start, end + 1) : cleaned;
  const parsed = JSON.parse(slice);
  return Array.isArray(parsed) ? parsed : [];
}

async function callGemini(vulnType, paramName, paramContext, overrides = {}) {
  const key = overrides.apiKey ?? config.GEMINI_API_KEY;
  if (!key) throw new Error('GEMINI_API_KEY not set');
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(config.GEMINI_MODEL)}:generateContent?key=${encodeURIComponent(key)}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ contents: [{ parts: [{ text: PROMPT(vulnType, paramName, paramContext) }] }] }),
  });
  if (!res.ok) {
    const e = new Error(`Gemini HTTP ${res.status}`);
    e.status = res.status;
    throw e;
  }
  const data = await res.json();
  const text = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
  return parseJsonArray(text);
}

async function callOllama(vulnType, paramName, paramContext, overrides = {}) {
  const base = overrides.baseUrl ?? config.OLLAMA_BASE_URL;
  const res = await fetch(`${base}/api/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: config.OLLAMA_MODEL, prompt: PROMPT(vulnType, paramName, paramContext), stream: false }),
  });
  if (!res.ok) {
    const e = new Error(`Ollama HTTP ${res.status}`);
    e.status = res.status;
    throw e;
  }
  const data = await res.json();
  return parseJsonArray(data?.response || '');
}

/** Test seam — reset the module-level circuit breaker between unit tests. */
export function _resetCircuitBreaker() {
  circuitOpen = false;
  circuitOpenedAt = 0;
}

/** Test/visibility helper. */
export function _circuitOpen() {
  return circuitOpen;
}
