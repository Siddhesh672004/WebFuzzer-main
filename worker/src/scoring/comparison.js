import { signature } from '@smartfuzz/shared/signatures';

// Comparison Engine (PRD §11) — diffs vulnerability sets across scans of the
// same target to produce FIXED / PERSISTS / NEW / REGRESSED status per finding.

export const COMPARE_STATUS = Object.freeze({
  VULNERABLE: 'VULNERABLE',
  FIXED: 'FIXED',
  NEW: 'NEW',
  REGRESSED: 'REGRESSED',
});

/**
 * Compare vulnerability sets across multiple scans (ordered oldest→newest).
 * @param {Array<{scanId, scanNumber, vulnerabilities: Array<{signature, type, severity, cvssScore, url, param}>}>} scans
 * @returns {ComparisonRow[]}
 */
export function compareScans(scans) {
  if (!scans || scans.length === 0) return [];

  // Build a map: signature → { meta, statusByScan: Map<scanNumber, status> }
  const bySignature = new Map();

  for (const scan of scans) {
    const sigSet = new Set((scan.vulnerabilities || []).map((v) => v.signature));

    for (const vuln of scan.vulnerabilities || []) {
      if (!bySignature.has(vuln.signature)) {
        bySignature.set(vuln.signature, {
          signature: vuln.signature,
          type: vuln.type,
          severity: vuln.severity,
          cvssScore: vuln.cvssScore,
          url: vuln.url,
          param: vuln.param,
          statusByScan: new Map(),
        });
      }
      bySignature.get(vuln.signature).statusByScan.set(scan.scanNumber, COMPARE_STATUS.VULNERABLE);
    }
  }

  // Second pass: compute FIXED / NEW / REGRESSED.
  for (const [, row] of bySignature) {
    const scanNumbers = scans.map((s) => s.scanNumber);
    for (let i = 0; i < scanNumbers.length; i++) {
      const n = scanNumbers[i];
      const wasPresent = i > 0 && row.statusByScan.get(scanNumbers[i - 1]) === COMPARE_STATUS.VULNERABLE;
      const isPresent = row.statusByScan.has(n);

      if (!isPresent && wasPresent) {
        row.statusByScan.set(n, COMPARE_STATUS.FIXED);
      } else if (isPresent && !wasPresent && i > 0) {
        // Was absent in the previous scan — check if it ever appeared before.
        const everSeen = scanNumbers.slice(0, i).some((prev) =>
          row.statusByScan.get(prev) === COMPARE_STATUS.VULNERABLE,
        );
        row.statusByScan.set(n, everSeen ? COMPARE_STATUS.REGRESSED : COMPARE_STATUS.NEW);
      }
      // VULNERABLE already set in first pass; absent in first scan = no entry (—).
    }
  }

  return [...bySignature.values()].map((row) => ({
    ...row,
    statusByScan: Object.fromEntries(row.statusByScan),
  }));
}

/**
 * Compute summary counts from a comparison result.
 * @param {ComparisonRow[]} rows
 * @param {number} latestScanNumber
 */
export function comparisonSummary(rows, latestScanNumber) {
  let fixed = 0, newlyFound = 0, persisting = 0, regressed = 0;
  for (const row of rows) {
    const status = row.statusByScan[latestScanNumber];
    if (status === COMPARE_STATUS.FIXED) fixed++;
    else if (status === COMPARE_STATUS.NEW) newlyFound++;
    else if (status === COMPARE_STATUS.VULNERABLE) persisting++;
    else if (status === COMPARE_STATUS.REGRESSED) regressed++;
  }
  return { fixed, newlyFound, persisting, regressed };
}
