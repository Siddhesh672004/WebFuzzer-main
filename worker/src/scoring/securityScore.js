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

/**
 * Aggregate CVSS headline stats for the executive summary.
 * @param {Array<{cvssScore?: number}>} vulnerabilities
 * @returns {{ maxCvssScore: number, avgCvssScore: number }}
 */
export function computeAggregateStats(vulnerabilities = []) {
  const scores = vulnerabilities
    .map((v) => (typeof v.cvssScore === 'number' ? v.cvssScore : 0))
    .filter((s) => s > 0);
  if (scores.length === 0) return { maxCvssScore: 0, avgCvssScore: 0 };
  const max = Math.max(...scores);
  const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
  return { maxCvssScore: +max.toFixed(1), avgCvssScore: +avg.toFixed(1) };
}
