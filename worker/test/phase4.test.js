import { describe, it, expect } from 'vitest';
import { computeCvss, parseVector } from '../src/scoring/cvss.js';
import { computeSecurityScore } from '../src/scoring/securityScore.js';
import { FIX_GUIDES, getFixGuide } from '../src/knowledge/fixGuides.js';
import { VULN_TYPE_KEYS } from '@smartfuzz/shared/vulnTypes';
import { compareScans, comparisonSummary, COMPARE_STATUS } from '../src/scoring/comparison.js';
import { buildReportJson, buildReportHtml, buildReportCsv, buildReportMarkdown } from '../src/scoring/reportGenerator.js';
import { signature } from '@smartfuzz/shared/signatures';

// ── CVSS Calculator ──
describe('computeCvss', () => {
  it('computes SQLi vector correctly (IMPLEMENTATION_PLAN §3.2 verified)', () => {
    const { score } = computeCvss('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
    expect(score).toBe(10.0);
  });

  it('computes reflected XSS vector correctly', () => {
    const { score } = computeCvss('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N');
    expect(score).toBe(6.1);
  });

  it('returns 0.0 for all-None impact', () => {
    const { score, severity } = computeCvss('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N');
    expect(score).toBe(0.0);
    expect(severity).toBe('informational');
  });

  it('uses scope-dependent PR weights (S:C, PR:L = 0.68)', () => {
    // With S:C and PR:L the score should be higher than with S:U and PR:L.
    const changed = computeCvss('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H');
    const unchanged = computeCvss('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H');
    expect(changed.score).toBeGreaterThan(unchanged.score);
  });

  it('maps severity bands correctly', () => {
    expect(computeCvss('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').severity).toBe('critical');
    expect(computeCvss('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N').severity).toBe('medium');
  });

  it('throws on an invalid vector', () => {
    expect(() => computeCvss('not-a-vector')).toThrow();
    expect(() => computeCvss('CVSS:3.1/AV:N/AC:L')).toThrow();
  });

  it('uses Appendix-A roundup (not Math.ceil)', () => {
    // A known edge case: 6.049... should round to 6.1, not 6.0.
    const { score } = computeCvss('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N');
    expect(score).toBe(6.1);
    // Verify it's exactly one decimal place.
    expect(String(score).split('.')[1]?.length).toBeLessThanOrEqual(1);
  });
});

// ── Security Score ──
describe('computeSecurityScore', () => {
  it('starts at 100 with no vulnerabilities', () => {
    expect(computeSecurityScore({})).toBe(100);
  });

  it('deducts per PRD §7.4 penalty table', () => {
    expect(computeSecurityScore({ critical: 1 })).toBe(80);
    expect(computeSecurityScore({ high: 1 })).toBe(90);
    expect(computeSecurityScore({ medium: 1 })).toBe(95);
    expect(computeSecurityScore({ low: 1 })).toBe(98);
    expect(computeSecurityScore({ informational: 1 })).toBe(100);
  });

  it('floors at 0 (never negative)', () => {
    expect(computeSecurityScore({ critical: 10, high: 10 })).toBe(0);
  });

  it('handles mixed severities', () => {
    // 1 critical (-20) + 2 high (-20) + 1 medium (-5) = 55
    expect(computeSecurityScore({ critical: 1, high: 2, medium: 1 })).toBe(55);
  });
});

// ── Fix Guides coverage ──
describe('fix guides', () => {
  it('every emittable vuln type has a fix guide (CI coverage gate)', () => {
    // The engine can emit any type in VULN_TYPE_KEYS. Every one must have a guide.
    const missing = VULN_TYPE_KEYS.filter((k) => !FIX_GUIDES[k]);
    expect(missing, `Missing fix guides for: ${missing.join(', ')}`).toHaveLength(0);
  });

  it('every guide has required fields', () => {
    for (const [type, guide] of Object.entries(FIX_GUIDES)) {
      expect(guide.what, `${type}.what`).toBeTruthy();
      expect(guide.why, `${type}.why`).toBeTruthy();
      expect(Array.isArray(guide.steps), `${type}.steps`).toBe(true);
      expect(guide.steps.length, `${type}.steps`).toBeGreaterThan(0);
      expect(guide.ref, `${type}.ref`).toMatch(/^https:\/\//);
    }
  });

  it('getFixGuide returns a fallback for unknown types', () => {
    const guide = getFixGuide('unknown_type_xyz');
    expect(guide.what).toBeTruthy();
    expect(guide.ref).toBeTruthy();
  });
});

// ── Comparison Engine ──
const mkVuln = (type, url, param) => ({
  signature: signature(type, url, param),
  type, severity: 'high', cvssScore: 7.5, url, param,
});

describe('compareScans', () => {
  it('returns [] for empty input', () => {
    expect(compareScans([])).toEqual([]);
  });

  it('marks a vuln present in scan 1 only as VULNERABLE in scan 1', () => {
    const scans = [
      { scanId: '1', scanNumber: 1, vulnerabilities: [mkVuln('sqli', '/login', 'user')] },
    ];
    const rows = compareScans(scans);
    expect(rows[0].statusByScan[1]).toBe(COMPARE_STATUS.VULNERABLE);
  });

  it('marks a fixed vuln as FIXED in scan 2', () => {
    const vuln = mkVuln('sqli', '/login', 'user');
    const scans = [
      { scanId: '1', scanNumber: 1, vulnerabilities: [vuln] },
      { scanId: '2', scanNumber: 2, vulnerabilities: [] },
    ];
    const rows = compareScans(scans);
    expect(rows[0].statusByScan[1]).toBe(COMPARE_STATUS.VULNERABLE);
    expect(rows[0].statusByScan[2]).toBe(COMPARE_STATUS.FIXED);
  });

  it('marks a new vuln in scan 2 as NEW', () => {
    const vuln = mkVuln('xss', '/search', 'q');
    const scans = [
      { scanId: '1', scanNumber: 1, vulnerabilities: [] },
      { scanId: '2', scanNumber: 2, vulnerabilities: [vuln] },
    ];
    const rows = compareScans(scans);
    expect(rows[0].statusByScan[2]).toBe(COMPARE_STATUS.NEW);
  });

  it('marks a re-appearing vuln as REGRESSED', () => {
    const vuln = mkVuln('sqli', '/login', 'user');
    const scans = [
      { scanId: '1', scanNumber: 1, vulnerabilities: [vuln] },
      { scanId: '2', scanNumber: 2, vulnerabilities: [] },
      { scanId: '3', scanNumber: 3, vulnerabilities: [vuln] },
    ];
    const rows = compareScans(scans);
    expect(rows[0].statusByScan[2]).toBe(COMPARE_STATUS.FIXED);
    expect(rows[0].statusByScan[3]).toBe(COMPARE_STATUS.REGRESSED);
  });

  it('handles multiple vulns across scans', () => {
    const sqli = mkVuln('sqli', '/login', 'user');
    const xss = mkVuln('xss', '/search', 'q');
    const scans = [
      { scanId: '1', scanNumber: 1, vulnerabilities: [sqli, xss] },
      { scanId: '2', scanNumber: 2, vulnerabilities: [xss] },
    ];
    const rows = compareScans(scans);
    const sqliRow = rows.find((r) => r.type === 'sqli');
    const xssRow = rows.find((r) => r.type === 'xss');
    expect(sqliRow.statusByScan[2]).toBe(COMPARE_STATUS.FIXED);
    expect(xssRow.statusByScan[2]).toBe(COMPARE_STATUS.VULNERABLE);
  });
});

describe('comparisonSummary', () => {
  it('counts correctly', () => {
    const rows = [
      { type: 'sqli', statusByScan: { 1: 'VULNERABLE', 2: 'FIXED' } },
      { type: 'xss', statusByScan: { 1: 'VULNERABLE', 2: 'VULNERABLE' } },
      { type: 'rce', statusByScan: { 2: 'NEW' } },
    ];
    const s = comparisonSummary(rows, 2);
    expect(s.fixed).toBe(1);
    expect(s.persisting).toBe(1);
    expect(s.newlyFound).toBe(1);
    expect(s.regressed).toBe(0);
  });
});

// ── Report Generator ──
const mockScan = { _id: 'scan1', targetUrl: 'https://x.com', targetDomain: 'x.com', scanNumber: 1, stats: { durationSeconds: 30 } };
const mockVulns = [
  { type: 'sqli', severity: 'critical', cvssScore: 10.0, url: 'https://x.com/login', param: 'user', evidence: 'SQL error' },
  { type: 'xss', severity: 'medium', cvssScore: 6.1, url: 'https://x.com/search', param: 'q', evidence: 'Reflected' },
];

describe('buildReportJson', () => {
  it('produces correct summary counts and score', () => {
    const r = buildReportJson(mockScan, mockVulns);
    expect(r.summary.critical).toBe(1);
    expect(r.summary.medium).toBe(1);
    expect(r.summary.securityScore).toBe(75); // 100 - 20 (critical) - 5 (medium)
    expect(r.summary.totalVulnerabilities).toBe(2);
  });

  it('enriches vulns with fix guides', () => {
    const r = buildReportJson(mockScan, mockVulns);
    expect(r.vulnerabilities[0].fixGuide).toBeDefined();
    expect(r.vulnerabilities[0].fixGuide.what).toBeTruthy();
  });

  it('includes comparison when prior scans provided', () => {
    const prior = [{ scanId: 'scan0', scanNumber: 0, vulnerabilities: [{ ...mockVulns[0], signature: signature('sqli', 'https://x.com/login', 'user') }] }];
    const r = buildReportJson({ ...mockScan, scanNumber: 1 }, mockVulns, prior);
    expect(r.comparison.hasPreviousScans).toBe(true);
  });
});

describe('buildReportHtml', () => {
  it('produces valid HTML with vulnerability data', () => {
    const r = buildReportJson(mockScan, mockVulns);
    const html = buildReportHtml(r);
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('sqli');
    expect(html).toContain('CRITICAL');
    expect(html).toContain('75/100');
  });
});

describe('buildReportCsv', () => {
  it('produces CSV with header and rows', () => {
    const r = buildReportJson(mockScan, mockVulns);
    const csv = buildReportCsv(r);
    expect(csv.split('\n')[0]).toContain('severity');
    expect(csv).toContain('sqli');
    expect(csv).toContain('xss');
  });
});

describe('buildReportMarkdown', () => {
  it('produces markdown with score and vuln table', () => {
    const r = buildReportJson(mockScan, mockVulns);
    const md = buildReportMarkdown(r);
    expect(md).toContain('# SmartFuzz Report');
    expect(md).toContain('75/100');
    expect(md).toContain('sqli');
  });
});
