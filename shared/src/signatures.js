import { createHash } from 'node:crypto';

// Stable vulnerability identity for cross-scan comparison (IMPLEMENTATION_PLAN §4.4).
//
//   signature = sha1(type + ":" + normalizedEndpointPath + ":" + parameter)
//
// Query strings and numeric IDs are stripped from the path so that, e.g.,
// `/user/1` and `/user/2` collapse to the same finding — otherwise every IDOR
// on a different id would look like a brand-new vuln on rescan. This signature
// is what powers FIXED / PERSISTS / NEW / REGRESSED status in the comparison engine.

/**
 * Normalize a URL or path to a stable comparison key:
 *  - drop scheme + host (compare by path only; host is fixed per target)
 *  - drop query string and fragment
 *  - replace numeric path segments with ':id'
 *  - replace long hex/uuid-ish segments with ':id'
 *  - collapse duplicate slashes, strip trailing slash (except root)
 *  - lowercase
 * @param {string} urlOrPath
 * @returns {string} normalized path, always starting with '/'
 */
export function normalizeEndpointPath(urlOrPath) {
  if (!urlOrPath || typeof urlOrPath !== 'string') return '/';

  let path = urlOrPath.trim();

  // Strip scheme://host if a full URL was passed.
  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(path)) {
      path = new URL(path).pathname;
    }
  } catch {
    // Not a parseable URL — fall through and treat the string as a path.
  }

  // Drop query and fragment.
  path = path.split('#')[0].split('?')[0];

  // Ensure leading slash.
  if (!path.startsWith('/')) path = `/${path}`;

  // Split, normalize each segment, drop empties (collapses '//').
  const segments = path.split('/').filter(Boolean).map((seg) => {
    // Pure numeric id → :id
    if (/^\d+$/.test(seg)) return ':id';
    // UUID → :id
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg)) return ':id';
    // Long hex blob (>= 16 hex chars: tokens, hashes) → :id
    if (/^[0-9a-f]{16,}$/i.test(seg)) return ':id';
    // Mongo ObjectId (24 hex) is covered by the rule above.
    return seg.toLowerCase();
  });

  const normalized = `/${segments.join('/')}`;
  // Strip trailing slash except for root.
  return normalized.length > 1 ? normalized.replace(/\/+$/, '') : '/';
}

/**
 * Compute the stable signature for a finding.
 * @param {string} type      vuln type key (e.g. 'sqli')
 * @param {string} endpoint  URL or path where it was found
 * @param {string} parameter the affected parameter name ('' for global findings)
 * @returns {string} 40-char sha1 hex
 */
export function signature(type, endpoint, parameter = '') {
  const normPath = normalizeEndpointPath(endpoint);
  const param = (parameter || '').trim().toLowerCase();
  const input = `${type}:${normPath}:${param}`;
  return createHash('sha1').update(input).digest('hex');
}

/** The raw signature input string (useful for debugging/tests). */
export function signatureInput(type, endpoint, parameter = '') {
  return `${type}:${normalizeEndpointPath(endpoint)}:${(parameter || '').trim().toLowerCase()}`;
}
