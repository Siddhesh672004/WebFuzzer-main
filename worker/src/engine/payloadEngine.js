import { Payload } from '@smartfuzz/shared/models';

// Payload Engine (PRD §9.5b) — loads payloads from Mongo by attack type,
// prioritized by successCount (historically effective first), capped per run.
// Injectable model for tests.

const DEFAULT_CAP = 100;

// Maps attack type → vuln type keys in the Payload collection.
const ATTACK_TO_VULN_TYPES = {
  sqli: ['sqli'],
  xss: ['xss'],
  path_traversal: ['path_traversal'],
  open_redirect: ['open_redirect'],
  ssrf: ['ssrf'],
  cmd_injection: ['cmd_injection'],
  ssti: ['ssti'],
  auth_bypass: ['sqli', 'auth_bypass'],
  idor: ['sqli', 'idor'],
  parameter_tampering: ['parameter_tampering'],
  mass_assignment: ['mass_assignment'],
  csrf: ['csrf'],
  nosql_injection: ['nosql_injection'],
  ldap_injection: ['ldap_injection'],
  xpath_injection: ['xpath_injection'],
  xxe: ['xxe'],
  jwt_alg_none: ['jwt_alg_none'],
  crlf_injection: ['crlf_injection'],
};

/**
 * Load payloads for a set of attack types.
 * @param {string[]} attackTypes
 * @param {object} [opts] { cap, model }
 * @returns {Promise<Array<{type,value,source,tags}>>}
 */
export async function loadPayloads(attackTypes, opts = {}) {
  const cap = opts.cap ?? DEFAULT_CAP;
  const model = opts.model || Payload;

  const vulnTypes = [...new Set(attackTypes.flatMap((a) => ATTACK_TO_VULN_TYPES[a] || [a]))];
  if (vulnTypes.length === 0) return [];

  const payloads = await model
    .find({ type: { $in: vulnTypes }, isActive: true })
    .sort({ successCount: -1 })
    .limit(cap)
    .lean();

  return payloads.map((p) => ({ type: p.type, value: p.value, source: p.source, tags: p.tags || [] }));
}

/** Increment successCount for a payload that confirmed a finding. */
export async function recordSuccess(type, value, model = Payload) {
  await model.updateOne({ type, value }, { $inc: { successCount: 1 } }).catch(() => {});
}
