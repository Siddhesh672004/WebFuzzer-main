import { computeSecurityScore } from './securityScore.js';
import { getFixGuide } from '../knowledge/fixGuides.js';
import { compareScans, comparisonSummary } from './comparison.js';

// Report Generator (PRD §12). Produces JSON + standalone HTML + CSV/Markdown +
// PDF from a completed scan's data. PDF uses pdfkit (pure-JS, no headless
// browser) so report generation stays dependency-light and deterministic.
//
// The HTML/PDF layouts are a professional pen-test report: cover, executive
// summary, risk matrix, findings-by-type, full findings table, per-finding
// detail (incl. exposed-secret + screenshot evidence), and remediation guidance.

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'informational'];
const SEV_COLORS = {
  critical: '#F85149', high: '#F78166', medium: '#D29922', low: '#58A6FF', informational: '#8B949E',
};

/**
 * Build the full report JSON structure.
 * @param {object} scan  Scan document (plain object)
 * @param {object[]} vulnerabilities  Vulnerability documents
 * @param {object[]} [priorScans]  Prior scan+vuln sets for comparison
 */
export function buildReportJson(scan, vulnerabilities, priorScans = []) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  for (const v of vulnerabilities) counts[v.severity] = (counts[v.severity] || 0) + 1;

  const securityScore = computeSecurityScore(counts);

  // Enrich each vuln with its fix guide.
  const enriched = vulnerabilities.map((v) => ({
    ...v,
    fixGuide: getFixGuide(v.type),
  }));

  // Comparison.
  let comparison = { hasPreviousScans: false, fixed: 0, newlyFound: 0, persisting: 0, regressed: 0, rows: [] };
  if (priorScans.length > 0) {
    const allScans = [
      ...priorScans,
      { scanId: scan._id || scan.id, scanNumber: scan.scanNumber, vulnerabilities },
    ].sort((a, b) => a.scanNumber - b.scanNumber);
    const rows = compareScans(allScans);
    const summary = comparisonSummary(rows, scan.scanNumber);
    comparison = { hasPreviousScans: true, ...summary, rows };
  }

  const topFindings = [...enriched]
    .sort((a, b) => (b.cvssScore || 0) - (a.cvssScore || 0))
    .slice(0, 3)
    .map((v) => ({ type: v.type, severity: v.severity, cvssScore: v.cvssScore, url: v.url, param: v.param }));

  return {
    meta: {
      targetUrl: scan.targetUrl,
      targetDomain: scan.targetDomain,
      scanNumber: scan.scanNumber,
      scanId: String(scan._id || scan.id),
      generatedAt: new Date().toISOString(),
      durationSeconds: scan.stats?.durationSeconds || 0,
    },
    summary: { ...counts, securityScore, totalVulnerabilities: vulnerabilities.length },
    topFindings,
    vulnerabilities: enriched,
    comparison,
  };
}

// ── derived helpers shared by HTML + PDF ──

/** Group findings by type with count + highest severity, sorted by severity. */
function groupByType(vulnerabilities) {
  const byType = new Map();
  for (const v of vulnerabilities) {
    const cur = byType.get(v.type) || { type: v.type, count: 0, maxSeverity: 'informational' };
    cur.count += 1;
    if (SEV_ORDER.indexOf(v.severity) < SEV_ORDER.indexOf(cur.maxSeverity)) cur.maxSeverity = v.severity;
    byType.set(v.type, cur);
  }
  return [...byType.values()].sort((a, b) => SEV_ORDER.indexOf(a.maxSeverity) - SEV_ORDER.indexOf(b.maxSeverity));
}

/** Plain-language executive summary narrative. */
function executiveSummary(score, counts, target, total) {
  if (total === 0) {
    return `The security assessment of ${target} found no vulnerabilities. The target demonstrates a strong security posture with a score of ${score}/100.`;
  }
  const parts = [];
  if (counts.critical > 0) parts.push(`${counts.critical} critical`);
  if (counts.high > 0) parts.push(`${counts.high} high`);
  const top = parts.join(' and ');
  const urgency = score < 40 ? 'Immediate remediation is required.'
    : score < 70 ? 'Prompt remediation is recommended.'
    : 'Remediation should be scheduled.';
  return `The security assessment of ${target} identified ${total} vulnerabilit${total === 1 ? 'y' : 'ies'}${top ? `, including ${top} severity issue${(counts.critical + counts.high) === 1 ? '' : 's'}` : ''}. The overall security score is ${score}/100. ${urgency}`;
}

/** Render a standalone professional HTML report (embedded CSS, no external deps). */
export function buildReportHtml(reportJson) {
  const { meta, summary, vulnerabilities, comparison } = reportJson;
  const score = summary.securityScore;
  const byType = groupByType(vulnerabilities);
  const exec = executiveSummary(score, summary, meta.targetDomain || meta.targetUrl, summary.totalVulnerabilities);
  const sorted = [...vulnerabilities].sort((a, b) => (b.cvssScore || 0) - (a.cvssScore || 0));

  const riskCards = SEV_ORDER.filter((s) => s !== 'informational').map((sev) => `
      <div class="risk-card ${sev}">
        <div class="risk-count">${summary[sev] || 0}</div>
        <div class="risk-label">${sev.toUpperCase()}</div>
      </div>`).join('');

  const byTypeRows = byType.map((t) => `
      <tr>
        <td>${esc(t.type)}</td>
        <td>${t.count}</td>
        <td><span class="badge" style="background:${SEV_COLORS[t.maxSeverity]}">${t.maxSeverity.toUpperCase()}</span></td>
      </tr>`).join('');

  const summaryRows = sorted.map((v, i) => `
      <tr>
        <td class="num">${i + 1}</td>
        <td>${esc(v.type)}</td>
        <td><span class="badge" style="background:${SEV_COLORS[v.severity] || '#8B949E'}">${v.severity.toUpperCase()}</span></td>
        <td class="mono">${(v.cvssScore ?? 0).toFixed(1)}</td>
        <td class="mono trunc">${esc(v.type === 'exposed_secret' ? v.jsFileUrl || v.url : v.url)}</td>
        <td>${v.markedFixedByUser ? '<span class="badge badge-fixed">FIXED</span>' : `<span class="badge" style="background:${SEV_COLORS[v.severity] || '#8B949E'}">OPEN</span>`}</td>
      </tr>`).join('');

  const findingPages = sorted.map((v) => renderFindingHtml(v)).join('');

  const compSection = comparison.hasPreviousScans ? `
  <section class="page">
    <h1>Comparison with Previous Scans</h1>
    <p class="meta">Fixed: ${comparison.fixed} &nbsp;|&nbsp; New: ${comparison.newlyFound} &nbsp;|&nbsp; Persisting: ${comparison.persisting} &nbsp;|&nbsp; Regressed: ${comparison.regressed}</p>
    <table class="vuln-table">
      <thead><tr><th>Type</th><th>Location</th>${Object.keys(comparison.rows[0]?.statusByScan || {}).map((n) => `<th>Scan #${n}</th>`).join('')}</tr></thead>
      <tbody>${comparison.rows.map((r) => `<tr><td>${esc(r.type)}</td><td class="mono trunc">${esc(r.url)}</td>${Object.values(r.statusByScan).map((s) => `<td><span class="status ${s}">${s}</span></td>`).join('')}</tr>`).join('')}</tbody>
    </table>
  </section>` : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SmartFuzz Security Report — ${esc(meta.targetDomain)} #${meta.scanNumber}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#1a202c;background:#fff;font-size:14px;line-height:1.6}
  .mono{font-family:'Courier New',monospace}
  .num{color:#9ca3af;font-weight:600}
  .trunc{max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  /* Cover */
  .cover{min-height:100vh;background:#0a0a0f;color:#e2e8f0;padding:60px;page-break-after:always;display:flex;flex-direction:column;justify-content:space-between}
  .cover-logo{font-family:'Courier New',monospace;font-size:13px;color:#3FB950;letter-spacing:.3em;text-transform:uppercase;margin-bottom:60px}
  .cover-title{font-size:46px;font-weight:700;color:#fff;line-height:1.1;margin-bottom:12px}
  .cover-title span{color:#3FB950}
  .cover-sub{font-size:18px;color:#94a3b8;margin-bottom:48px}
  .cover-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:48px}
  .cover-item{border-left:3px solid #3FB950;padding-left:14px}
  .cover-k{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:#475569;margin-bottom:4px}
  .cover-v{font-size:15px;color:#e2e8f0;font-weight:500;word-break:break-all}
  .cover-score{display:flex;align-items:center;gap:24px}
  .score-circle{width:104px;height:104px;border-radius:50%;background:#111118;border:4px solid ${scoreColor(score)};display:flex;flex-direction:column;align-items:center;justify-content:center}
  .score-num{font-size:34px;font-weight:700;color:${scoreColor(score)};line-height:1}
  .score-den{font-size:10px;color:#94a3b8;text-transform:uppercase}
  .risk-band{font-size:22px;font-weight:700;color:${scoreColor(score)}}
  .confidential{background:#1e1e2e;border:1px solid #2d2d42;border-radius:6px;padding:12px 18px;font-size:12px;color:#94a3b8}
  /* Content */
  .page{padding:44px 56px;page-break-after:always}
  h1{font-size:26px;font-weight:700;color:#0a0a0f;border-bottom:3px solid #3FB950;padding-bottom:10px;margin-bottom:24px}
  h2{font-size:17px;font-weight:600;margin:24px 0 10px}
  p{color:#4b5563;margin-bottom:12px}
  .meta{color:#6b7280;font-size:13px}
  .exec-box{background:#f8fafc;border-left:4px solid #0a0a0f;border-radius:0 8px 8px 0;padding:18px 22px;margin:16px 0;font-size:15px;color:#1a202c}
  .risk-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:16px 0}
  .risk-card{border-radius:10px;padding:18px;text-align:center}
  .risk-card.critical{background:rgba(248,81,73,.08);border:1px solid #F85149}
  .risk-card.high{background:rgba(247,129,102,.08);border:1px solid #F78166}
  .risk-card.medium{background:rgba(210,153,34,.08);border:1px solid #D29922}
  .risk-card.low{background:rgba(88,166,255,.08);border:1px solid #58A6FF}
  .risk-count{font-size:38px;font-weight:700;line-height:1}
  .risk-label{font-size:11px;text-transform:uppercase;letter-spacing:.1em;margin-top:4px;font-weight:600}
  .risk-card.critical .risk-count,.risk-card.critical .risk-label{color:#F85149}
  .risk-card.high .risk-count,.risk-card.high .risk-label{color:#F78166}
  .risk-card.medium .risk-count,.risk-card.medium .risk-label{color:#b45309}
  .risk-card.low .risk-count,.risk-card.low .risk-label{color:#58A6FF}
  .score-bar{background:#e5e7eb;border-radius:100px;height:12px;margin:8px 0;overflow:hidden}
  .score-fill{height:100%;border-radius:100px;background:${scoreColor(score)};width:${score}%}
  table.vuln-table{width:100%;border-collapse:collapse;margin:14px 0;font-size:13px}
  .vuln-table th{background:#0a0a0f;color:#fff;padding:9px 12px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.05em}
  .vuln-table td{padding:9px 12px;border-bottom:1px solid #e5e7eb;vertical-align:top}
  .vuln-table tr:nth-child(even) td{background:#f9fafb}
  .badge{display:inline-block;padding:2px 9px;border-radius:100px;font-size:11px;font-weight:700;color:#fff;text-transform:uppercase}
  .badge-fixed{background:#3FB950}
  .status{font-weight:700;font-size:12px}
  .status.FIXED{color:#3FB950}.status.NEW{color:#F78166}.status.VULNERABLE{color:#F85149}.status.REGRESSED{color:#D29922}
  /* Finding detail */
  .finding{padding:40px 56px;page-break-after:always;border-top:1px solid #eee}
  .finding-head{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:2px solid #e5e7eb;padding-bottom:14px;margin-bottom:18px}
  .finding-title{font-size:21px;font-weight:700;color:#0a0a0f}
  .finding-score{background:#0a0a0f;color:#3FB950;font-family:'Courier New',monospace;font-size:26px;font-weight:700;padding:6px 14px;border-radius:8px}
  .kv{display:grid;grid-template-columns:auto 1fr;gap:6px 18px;font-size:13px;margin-bottom:16px}
  .kv .k{color:#6b7280;font-weight:600;white-space:nowrap}
  .kv .v{color:#1a202c;word-break:break-all;font-family:'Courier New',monospace}
  .section-label{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:#9ca3af;font-weight:700;margin:16px 0 6px}
  .code{background:#0a0a0f;color:#3FB950;font-family:'Courier New',monospace;font-size:12px;padding:14px;border-radius:8px;white-space:pre-wrap;word-break:break-word;line-height:1.5}
  .warn{background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;padding:14px;font-family:'Courier New',monospace;font-size:12px}
  .info{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:14px}
  ul.steps{padding-left:20px;color:#4b5563;line-height:1.9}
  .foot{margin-top:40px;padding-top:20px;border-top:2px solid #e5e7eb;text-align:center;color:#9ca3af;font-size:12px}
</style>
</head>
<body>

<div class="cover">
  <div>
    <div class="cover-logo">▶ SmartFuzz Security Scanner</div>
    <div class="cover-title">Web Application<br><span>Security Report</span></div>
    <div class="cover-sub">Automated Penetration Testing Assessment</div>
    <div class="cover-grid">
      <div class="cover-item"><div class="cover-k">Target</div><div class="cover-v">${esc(meta.targetUrl)}</div></div>
      <div class="cover-item"><div class="cover-k">Report ID</div><div class="cover-v">SF-${esc(meta.scanId.slice(-8).toUpperCase())}</div></div>
      <div class="cover-item"><div class="cover-k">Scan Number</div><div class="cover-v">#${meta.scanNumber}</div></div>
      <div class="cover-item"><div class="cover-k">Generated</div><div class="cover-v">${esc(formatDate(meta.generatedAt))}</div></div>
    </div>
    <div class="cover-score">
      <div class="score-circle"><div class="score-num">${score}</div><div class="score-den">/ 100</div></div>
      <div><div class="risk-band">${riskBand(score)}</div><div class="meta">Security Score: ${score} / 100</div></div>
    </div>
  </div>
  <div class="confidential">⚠ CONFIDENTIAL — Contains sensitive security information. Limit distribution to authorized personnel. Generated by SmartFuzz on ${esc(formatDate(meta.generatedAt))}.</div>
</div>

<section class="page">
  <h1>1. Executive Summary</h1>
  <div class="exec-box">${esc(exec)}</div>
  <h2>Risk Overview</h2>
  <div class="risk-grid">${riskCards}</div>
  <h2>Security Score</h2>
  <div style="display:flex;align-items:center;gap:16px">
    <div style="flex:1"><div class="score-bar"><div class="score-fill"></div></div></div>
    <div style="font-size:24px;font-weight:700;min-width:72px;text-align:right">${score}/100</div>
  </div>
  <p style="font-size:13px">Score = 100 − Σ(severity penalty). 90+ is low risk.</p>
  ${byType.length ? `<h2>Findings by Type</h2>
  <table class="vuln-table"><thead><tr><th>Vulnerability Type</th><th>Count</th><th>Highest Severity</th></tr></thead><tbody>${byTypeRows}</tbody></table>` : ''}
</section>

<section class="page">
  <h1>2. Vulnerability Summary</h1>
  ${sorted.length === 0 ? `<div class="info"><strong style="color:#065f46">✅ No vulnerabilities detected.</strong><p style="margin-top:6px;color:#047857">The automated assessment found no security issues. Regular rescanning is recommended as the application evolves.</p></div>`
    : `<table class="vuln-table"><thead><tr><th>#</th><th>Vulnerability</th><th>Severity</th><th>CVSS</th><th>Location</th><th>Status</th></tr></thead><tbody>${summaryRows}</tbody></table>`}
</section>

${findingPages}
${compSection}

<section class="page">
  <h1>${comparison.hasPreviousScans ? '4' : '3'}. Remediation Guidance</h1>
  ${summary.critical > 0 ? `<div class="warn"><strong style="color:#c2410c">🔴 Immediate Action Required</strong><p style="margin-top:6px">${summary.critical} critical vulnerabilit${summary.critical === 1 ? 'y' : 'ies'} must be addressed before production use.</p></div>` : ''}
  <h2>General Hardening Recommendations</h2>
  <ul class="steps">
    <li>Implement a Content-Security-Policy (CSP) to mitigate XSS impact.</li>
    <li>Enable all security headers: HSTS, X-Frame-Options, X-Content-Type-Options.</li>
    <li>Use parameterized queries for all database interactions.</li>
    <li>Rotate any exposed credentials immediately and move secrets to server-side env vars.</li>
    <li>Add automated secret scanning to your CI/CD pipeline.</li>
    <li>Schedule regular security rescans after significant code changes.</li>
  </ul>
  <div class="foot">
    <p>Report generated by <strong>SmartFuzz</strong> — Scan #${meta.scanNumber} — ${esc(formatDate(meta.generatedAt))}</p>
    <p style="margin-top:4px">Automated assessment — results should be reviewed by a qualified security professional. Authorized security testing only.</p>
  </div>
</section>

</body>
</html>`;
}

/** Render one finding's detail section. */
function renderFindingHtml(v) {
  const isSecret = v.type === 'exposed_secret';
  const guide = v.fixGuide || {};
  const rows = [
    isSecret
      ? ['JS File', v.jsFileUrl || v.url]
      : ['Endpoint', v.url],
    v.param && !isSecret ? ['Parameter', v.param] : null,
    isSecret && v.secretType ? ['Secret Type', v.secretType] : null,
    isSecret && v.lineNumber ? ['Line', String(v.lineNumber)] : null,
    v.cvssVector ? ['CVSS Vector', v.cvssVector] : null,
    v.owaspRef ? ['OWASP', v.owaspRef] : null,
  ].filter(Boolean);

  return `
<section class="finding">
  <div class="finding-head">
    <div>
      <div style="margin-bottom:8px"><span class="badge" style="background:${SEV_COLORS[v.severity] || '#8B949E'}">${v.severity.toUpperCase()}</span></div>
      <div class="finding-title">${esc(v.type)}</div>
    </div>
    <div class="finding-score">${(v.cvssScore ?? 0).toFixed(1)}</div>
  </div>
  <div class="kv">${rows.map(([k, val]) => `<span class="k">${esc(k)}:</span><span class="v">${esc(val)}</span>`).join('')}</div>
  ${v.payload ? `<div class="section-label">Payload Used</div><div class="code">${esc(v.payload)}</div>` : ''}
  ${isSecret && v.matchPreview ? `<div class="section-label">Secret Preview (Masked)</div><div class="code">${esc(v.matchPreview)}</div>` : ''}
  <div class="section-label">Evidence</div>
  <div class="warn">${esc(v.evidence) || 'See request/response proof.'}</div>
  ${v.screenshotFile ? `<div class="section-label">Visual Evidence</div><p style="font-size:12px;color:#6b7280">📸 Screenshot captured at detection (${esc(v.screenshotFile)}). View in SmartFuzz for the full image.</p>` : ''}
  ${guide.what ? `<div class="section-label">Why It Matters</div><p>${esc(guide.what)} ${esc(guide.why || '')}</p>` : ''}
  ${Array.isArray(guide.steps) && guide.steps.length ? `<div class="section-label">How to Fix</div><ul class="steps">${guide.steps.map((s) => `<li>${esc(s)}</li>`).join('')}</ul>` : ''}
  ${guide.after ? `<div class="section-label">Recommended Code</div><div class="code">${esc(guide.after)}</div>` : ''}
  ${v.markedFixedByUser ? `<div class="info">✅ This vulnerability has been marked as fixed.</div>` : ''}
</section>`;
}

/** CSV export of vulnerabilities (now includes secret columns). */
export function buildReportCsv(reportJson) {
  const header = 'severity,type,url,param,cvssScore,secretType,jsFileUrl,lineNumber,evidence';
  const rows = reportJson.vulnerabilities.map((v) =>
    [v.severity, v.type, v.url, v.param, v.cvssScore, v.secretType || '', v.jsFileUrl || '', v.lineNumber ?? '', (v.evidence || '').replace(/,/g, ';')].map(csvEsc).join(','),
  );
  return [header, ...rows].join('\n');
}

/** Markdown summary. */
export function buildReportMarkdown(reportJson) {
  const { meta, summary, vulnerabilities } = reportJson;
  const lines = [
    `# SmartFuzz Report — ${meta.targetDomain} Scan #${meta.scanNumber}`,
    ``,
    `**Target:** ${meta.targetUrl}  `,
    `**Score:** ${summary.securityScore}/100  `,
    `**Generated:** ${meta.generatedAt}`,
    ``,
    `## Summary`,
    `| Severity | Count |`,
    `|---|---|`,
    `| Critical | ${summary.critical} |`,
    `| High | ${summary.high} |`,
    `| Medium | ${summary.medium} |`,
    `| Low | ${summary.low} |`,
    `| Informational | ${summary.informational} |`,
    ``,
    `## Vulnerabilities`,
    `| Severity | Type | Location | Param | CVSS |`,
    `|---|---|---|---|---|`,
    ...vulnerabilities.map((v) => `| ${v.severity} | ${v.type} | ${v.type === 'exposed_secret' ? (v.jsFileUrl || v.url) : v.url} | ${v.param} | ${v.cvssScore} |`),
  ];
  return lines.join('\n');
}

// ── helpers ──
function esc(s) { return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
function csvEsc(s) { const str = String(s ?? ''); return str.includes(',') ? `"${str}"` : str; }
function scoreColor(s) { if (s >= 80) return '#3FB950'; if (s >= 50) return '#D29922'; return '#F85149'; }
function riskBand(s) { if (s >= 90) return 'LOW RISK'; if (s >= 70) return 'MEDIUM RISK'; if (s >= 40) return 'HIGH RISK'; return 'CRITICAL RISK'; }
function formatDate(d) {
  try { return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }); }
  catch { return String(d); }
}

/**
 * Build a PDF report buffer using pdfkit (pure-JS, no headless browser).
 * Professional layout: title page, score, severity breakdown, per-finding
 * detail (incl. secret preview + remediation). Returns a Promise<Buffer>.
 */
export async function buildReportPdf(reportJson) {
  const PDFDocument = (await import('pdfkit')).default;
  const { meta, summary, vulnerabilities } = reportJson;
  const score = summary.securityScore;
  const sorted = [...vulnerabilities].sort((a, b) => (b.cvssScore || 0) - (a.cvssScore || 0));

  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50, size: 'A4', bufferPages: true });
    const chunks = [];
    doc.on('data', (c) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    const scoreClr = scoreColor(score);

    // ── Title page ──
    doc.fontSize(11).fillColor('#3FB950').text('▶ SMARTFUZZ SECURITY SCANNER', { characterSpacing: 2 });
    doc.moveDown(2);
    doc.fontSize(30).fillColor('#0a0a0f').text('Web Application');
    doc.fillColor('#3FB950').text('Security Report');
    doc.moveDown(0.5);
    doc.fontSize(13).fillColor('#6b7280').text('Automated Penetration Testing Assessment');
    doc.moveDown(2);

    doc.fontSize(10).fillColor('#6b7280');
    doc.text(`Target:        `, { continued: true }).fillColor('#1a202c').text(meta.targetUrl);
    doc.fillColor('#6b7280').text(`Report ID:     `, { continued: true }).fillColor('#1a202c').text(`SF-${meta.scanId.slice(-8).toUpperCase()}`);
    doc.fillColor('#6b7280').text(`Scan Number:   `, { continued: true }).fillColor('#1a202c').text(`#${meta.scanNumber}`);
    doc.fillColor('#6b7280').text(`Generated:     `, { continued: true }).fillColor('#1a202c').text(formatDate(meta.generatedAt));
    doc.moveDown(2);

    doc.fontSize(54).fillColor(scoreClr).text(`${score}`, { continued: true }).fontSize(20).fillColor('#6b7280').text(' / 100');
    doc.fontSize(16).fillColor(scoreClr).text(riskBand(score));
    doc.moveDown(2);
    doc.fontSize(8).fillColor('#94a3b8').text('CONFIDENTIAL — Limit distribution to authorized personnel. Authorized security testing only.', { width: 400 });

    // ── Executive summary ──
    doc.addPage();
    doc.fontSize(20).fillColor('#0a0a0f').text('Executive Summary');
    doc.moveTo(50, doc.y + 2).lineTo(545, doc.y + 2).strokeColor('#3FB950').lineWidth(2).stroke();
    doc.moveDown(0.8);
    doc.fontSize(11).fillColor('#1a202c').text(executiveSummary(score, summary, meta.targetDomain || meta.targetUrl, summary.totalVulnerabilities), { align: 'left' });
    doc.moveDown(1);

    doc.fontSize(13).fillColor('#0a0a0f').text('Risk Overview');
    doc.moveDown(0.4);
    doc.fontSize(10);
    for (const sev of SEV_ORDER) {
      doc.fillColor(SEV_COLORS[sev]).text(`■ `, { continued: true })
        .fillColor('#1a202c').text(`${sev.toUpperCase()}: ${summary[sev] || 0}`);
    }
    doc.moveDown(0.5);
    doc.fontSize(10).fillColor('#6b7280').text(`Total findings: ${summary.totalVulnerabilities}`);

    // ── Findings table ──
    doc.moveDown(1.2);
    doc.fontSize(13).fillColor('#0a0a0f').text('Vulnerability Summary');
    doc.moveDown(0.5);

    if (sorted.length === 0) {
      doc.fontSize(10).fillColor('#3FB950').text('✅ No vulnerabilities found.');
    } else {
      const cols = [60, 110, 170, 60, 60]; // sev, type, location, cvss
      const startX = doc.page.margins.left;
      let y = doc.y;
      doc.fontSize(9).fillColor('#8B949E');
      ['SEVERITY', 'TYPE', 'LOCATION', 'CVSS'].forEach((h, i) => {
        doc.text(h, startX + cols.slice(0, i).reduce((a, b) => a + b, 0), y, { width: cols[i], lineBreak: false });
      });
      y += 15;
      doc.moveTo(startX, y).lineTo(startX + 400, y).strokeColor('#30363D').lineWidth(1).stroke();
      y += 4;
      for (const v of sorted.slice(0, 60)) {
        if (y > doc.page.height - 80) { doc.addPage(); y = doc.page.margins.top; }
        const loc = (v.type === 'exposed_secret' ? (v.jsFileUrl || v.url) : v.url) || '';
        doc.fontSize(8).fillColor(SEV_COLORS[v.severity] || '#1a202c');
        doc.text(v.severity.toUpperCase(), startX, y, { width: cols[0], lineBreak: false });
        doc.fillColor('#1a202c');
        doc.text(v.type, startX + cols[0], y, { width: cols[1], lineBreak: false });
        doc.text(loc.slice(0, 42), startX + cols[0] + cols[1], y, { width: cols[2], lineBreak: false });
        doc.text(String((v.cvssScore ?? 0).toFixed(1)), startX + cols[0] + cols[1] + cols[2], y, { width: cols[3], lineBreak: false });
        y += 13;
      }
      if (sorted.length > 60) {
        doc.fontSize(8).fillColor('#8B949E').text(`... and ${sorted.length - 60} more (see HTML report).`, startX, y + 4);
      }
    }

    // ── Per-finding detail (top 25 to keep PDF bounded) ──
    for (const v of sorted.slice(0, 25)) {
      doc.addPage();
      const isSecret = v.type === 'exposed_secret';
      doc.fontSize(9).fillColor(SEV_COLORS[v.severity] || '#8B949E').text(v.severity.toUpperCase());
      doc.fontSize(18).fillColor('#0a0a0f').text(v.type, { continued: true })
        .fontSize(16).fillColor(scoreColor(0)).text(`   ${(v.cvssScore ?? 0).toFixed(1)}`);
      doc.moveTo(50, doc.y + 2).lineTo(545, doc.y + 2).strokeColor('#e5e7eb').lineWidth(1).stroke();
      doc.moveDown(0.6);

      doc.fontSize(9).fillColor('#6b7280');
      const kv = (k, val) => { if (val) doc.fillColor('#6b7280').text(`${k}: `, { continued: true }).fillColor('#1a202c').text(String(val)); };
      kv(isSecret ? 'JS File' : 'Endpoint', isSecret ? (v.jsFileUrl || v.url) : v.url);
      if (!isSecret) kv('Parameter', v.param);
      if (isSecret) { kv('Secret Type', v.secretType); kv('Line', v.lineNumber); kv('Preview', v.matchPreview); }
      kv('CVSS Vector', v.cvssVector);
      kv('OWASP', v.owaspRef);
      doc.moveDown(0.6);

      if (v.payload) {
        doc.fontSize(8).fillColor('#9ca3af').text('PAYLOAD');
        doc.fontSize(9).fillColor('#1a202c').text(String(v.payload), { width: 480 });
        doc.moveDown(0.4);
      }
      doc.fontSize(8).fillColor('#9ca3af').text('EVIDENCE');
      doc.fontSize(9).fillColor('#1a202c').text(v.evidence || 'See request/response proof.', { width: 480 });

      const guide = v.fixGuide || {};
      if (guide.what) {
        doc.moveDown(0.4);
        doc.fontSize(8).fillColor('#9ca3af').text('WHY IT MATTERS');
        doc.fontSize(9).fillColor('#1a202c').text(`${guide.what} ${guide.why || ''}`, { width: 480 });
      }
      if (Array.isArray(guide.steps) && guide.steps.length) {
        doc.moveDown(0.4);
        doc.fontSize(8).fillColor('#9ca3af').text('HOW TO FIX');
        doc.fontSize(9).fillColor('#1a202c');
        guide.steps.forEach((s) => doc.text(`• ${s}`, { width: 480 }));
      }
      if (v.screenshotFile) {
        doc.moveDown(0.4);
        doc.fontSize(8).fillColor('#6b7280').text(`📸 Screenshot evidence captured (${v.screenshotFile}) — view in SmartFuzz.`);
      }
    }

    // ── Footer on every page ──
    const range = doc.bufferedPageRange();
    for (let i = range.start; i < range.start + range.count; i++) {
      doc.switchToPage(i);
      doc.fontSize(8).fillColor('#9ca3af')
        .text(`SmartFuzz Security Report — CONFIDENTIAL — Scan #${meta.scanNumber}`,
          50, doc.page.height - 35, { width: 495, align: 'center' });
    }

    doc.end();
  });
}
