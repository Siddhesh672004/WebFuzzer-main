// CVSS v3.1 base score calculator (IMPLEMENTATION_PLAN §3.2).
// Uses the Appendix-A integer-arithmetic roundup from the FIRST.org spec —
// NOT Math.ceil — to avoid the 0.1 float-representation edge cases that would
// fail a spot-check against NVD. Scope-dependent PR values are handled correctly.

// Metric weights from CVSS v3.1 specification.
const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC = { L: 0.77, H: 0.44 };
const PR_UNCHANGED = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED = { N: 0.85, L: 0.68, H: 0.5 }; // scope-dependent
const UI = { N: 0.85, R: 0.62 };
const S = { U: 'unchanged', C: 'changed' };
const C_I_A = { N: 0, L: 0.22, H: 0.56 };

/**
 * Parse a CVSS:3.1 vector string into metric values.
 * @param {string} vector e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
 * @returns {object} { AV, AC, PR, UI, S, C, I, A }
 */
export function parseVector(vector) {
  if (!vector || !vector.startsWith('CVSS:3.1/')) {
    throw new Error(`Invalid CVSS:3.1 vector: ${vector}`);
  }
  const parts = vector.slice('CVSS:3.1/'.length).split('/');
  const m = {};
  for (const part of parts) {
    const [k, v] = part.split(':');
    m[k] = v;
  }
  const required = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
  for (const k of required) {
    if (!m[k]) throw new Error(`Missing metric ${k} in vector: ${vector}`);
  }
  return m;
}

/**
 * Compute the CVSS v3.1 base score from a vector string.
 * Returns { score: number (1 decimal), severity: string, vector }.
 */
export function computeCvss(vector) {
  const m = parseVector(vector);
  const scope = m.S === 'C' ? 'changed' : 'unchanged';

  const avW = AV[m.AV];
  const acW = AC[m.AC];
  const prW = scope === 'changed' ? PR_CHANGED[m.PR] : PR_UNCHANGED[m.PR];
  const uiW = UI[m.UI];
  const cW = C_I_A[m.C];
  const iW = C_I_A[m.I];
  const aW = C_I_A[m.A];

  if (avW === undefined || acW === undefined || prW === undefined || uiW === undefined) {
    throw new Error(`Unknown metric value in vector: ${vector}`);
  }

  const iss = 1 - (1 - cW) * (1 - iW) * (1 - aW);

  let impact;
  if (scope === 'unchanged') {
    impact = 6.42 * iss;
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  }

  const exploitability = 8.22 * avW * acW * prW * uiW;

  if (impact <= 0) return { score: 0.0, severity: 'informational', vector };

  let baseScore;
  if (scope === 'unchanged') {
    baseScore = Math.min(impact + exploitability, 10);
  } else {
    baseScore = Math.min(1.08 * (impact + exploitability), 10);
  }

  // Appendix-A roundup: smallest value >= x with exactly 1 decimal place.
  const rounded = roundup(baseScore);
  const severity = cvssToSeverity(rounded);
  return { score: rounded, severity, vector };
}

/** CVSS v3.1 Appendix-A integer-arithmetic roundup. */
function roundup(x) {
  const intX = Math.round(x * 100000);
  if (intX % 10000 === 0) return intX / 100000;
  return (Math.floor(intX / 10000) + 1) / 10;
}

function cvssToSeverity(score) {
  if (score === 0) return 'informational';
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  return 'low';
}
