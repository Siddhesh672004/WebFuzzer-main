// Severity bands (CVSS v3.1 qualitative scale, FIRST.org / NVD).
// Single source of truth for label, numeric range, and UI color.

export const SEVERITY = Object.freeze({
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFORMATIONAL: 'informational',
});

// Ordered high → low for sorting/iteration.
export const SEVERITY_ORDER = Object.freeze([
  SEVERITY.CRITICAL,
  SEVERITY.HIGH,
  SEVERITY.MEDIUM,
  SEVERITY.LOW,
  SEVERITY.INFORMATIONAL,
]);

// Numeric rank for sorting (higher = more severe).
export const SEVERITY_RANK = Object.freeze({
  [SEVERITY.CRITICAL]: 4,
  [SEVERITY.HIGH]: 3,
  [SEVERITY.MEDIUM]: 2,
  [SEVERITY.LOW]: 1,
  [SEVERITY.INFORMATIONAL]: 0,
});

// Band metadata: inclusive numeric ranges + the hacker-theme palette from the PRD.
export const SEVERITY_BANDS = Object.freeze({
  [SEVERITY.CRITICAL]: { min: 9.0, max: 10.0, color: '#F85149', label: 'CRITICAL' },
  [SEVERITY.HIGH]: { min: 7.0, max: 8.9, color: '#F78166', label: 'HIGH' },
  [SEVERITY.MEDIUM]: { min: 4.0, max: 6.9, color: '#D29922', label: 'MEDIUM' },
  [SEVERITY.LOW]: { min: 0.1, max: 3.9, color: '#58A6FF', label: 'LOW' },
  [SEVERITY.INFORMATIONAL]: { min: 0.0, max: 0.0, color: '#8B949E', label: 'INFORMATIONAL' },
});

// Penalty applied to the 0–100 overall Security Score per finding (PRD §7.4).
export const SECURITY_SCORE_PENALTY = Object.freeze({
  [SEVERITY.CRITICAL]: 20,
  [SEVERITY.HIGH]: 10,
  [SEVERITY.MEDIUM]: 5,
  [SEVERITY.LOW]: 2,
  [SEVERITY.INFORMATIONAL]: 0,
});

/**
 * Map a CVSS base score to its qualitative severity label.
 * Uses the official CVSS v3.1 rating scale. 0.0 → informational.
 * @param {number} score 0.0–10.0
 * @returns {string} one of SEVERITY.*
 */
export function severityFromScore(score) {
  if (typeof score !== 'number' || Number.isNaN(score)) {
    throw new TypeError(`severityFromScore expects a number, got ${typeof score}`);
  }
  if (score <= 0) return SEVERITY.INFORMATIONAL;
  if (score >= 9.0) return SEVERITY.CRITICAL;
  if (score >= 7.0) return SEVERITY.HIGH;
  if (score >= 4.0) return SEVERITY.MEDIUM;
  return SEVERITY.LOW;
}

/** Color for a severity label (falls back to informational gray). */
export function severityColor(severity) {
  return (SEVERITY_BANDS[severity] || SEVERITY_BANDS[SEVERITY.INFORMATIONAL]).color;
}
