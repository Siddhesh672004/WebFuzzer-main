import { getVulnType } from '@smartfuzz/shared/vulnTypes';
import { vectorFor } from '@smartfuzz/shared/cvssVectors';
import { severityFromScore } from '@smartfuzz/shared/severity';
import { signature } from '@smartfuzz/shared/signatures';

// Finding factory — single place that turns a detection into a normalized
// vulnerability record. Pulls the OWASP ref + CVSS vector/score from the shared
// registry so every module produces consistent, scored findings with a stable
// signature for cross-scan diffing. (Phase 4's CVSS calculator will recompute
// the score from the vector and assert it matches expectedScore.)

/**
 * @param {object} f
 *   type      vuln type key (required)
 *   subtype?  subtype id
 *   url?      where it was found
 *   param?    affected parameter ('' for global)
 *   payload?, evidence?, request?, response?, isMutation?, parentPayload?, cveId?
 *   cvssScore? override (e.g. CVE-derived); else taken from the registry vector
 * @returns normalized finding ready to persist as a Vulnerability
 */
export function makeFinding(f) {
  const meta = getVulnType(f.type); // throws on unknown type
  const { vector, expectedScore } = vectorFor(f.type, f.subtype || '');
  const cvssScore = typeof f.cvssScore === 'number' ? f.cvssScore : expectedScore;
  const severity = severityFromScore(cvssScore);

  return {
    type: f.type,
    subtype: f.subtype || '',
    severity,
    cvssScore,
    cvssVector: f.cvssVector || vector,
    url: f.url || '',
    param: f.param || '',
    payload: f.payload || '',
    isMutation: !!f.isMutation,
    parentPayload: f.parentPayload || '',
    request: f.request || {},
    response: f.response || {},
    evidence: f.evidence || '',
    owaspRef: meta.owaspRef,
    cveId: f.cveId || '',
    signature: signature(f.type, f.url || '', f.param || ''),
    confirmedAt: new Date(),
  };
}
