import { SECURITY_SCORE_PENALTY, SEVERITY_ORDER } from '@smartfuzz/shared/severity';

// Overall Security Score (PRD §7.4): 100 − penalties, floored at 0.

/**
 * Compute the 0–100 security score from vulnerability counts.
 * @param {{ critical, high, medium, low, informational }} counts
 * @returns {number}
 */
export function computeSecurityScore(counts = {}) {
  let score = 100;
  for (const sev of SEVERITY_ORDER) {
    const n = counts[sev] || 0;
    score -= n * (SECURITY_SCORE_PENALTY[sev] || 0);
  }
  return Math.max(0, score);
}
