import { computeSecurityScore } from './securityScore.js';
import { getFixGuide } from '../knowledge/fixGuides.js';
import { compareScans, comparisonSummary } from './comparison.js';

// Report Generator (PRD §12). Produces JSON + standalone HTML from a completed
// scan's data. PDF generation uses pdfkit (Phase 6 polish); CSV/Markdown are
// lightweight string transforms.

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

/** Render a standalone HTML report (embedded CSS, no external deps). */
export function buildReportHtml(reportJson) {
  const { meta, summary, vulnerabilities, comparison } = reportJson;
  const severityColor = { critical: '#F85149', high: '#F78166', medium: '#D29922', low: '#58A6FF', informational: '#8B949E' };

  const vulnRows = vulnerabilities.map((v) => `
    <tr>
      <td><span class="badge" style="background:${severityColor[v.severity] || '#8B949E'}">${v.severity.toUpperCase()}</span></td>
      <td>${esc(v.type)}</td>
      <td>${esc(v.url)}</td>
      <td>${esc(v.param)}</td>
      <td>${v.cvssScore?.toFixed(1) || '0.0'}</td>
    </tr>`).join('');

  const compRows = comparison.hasPreviousScans
    ? comparison.rows.map((r) => {
        const statuses = Object.entries(r.statusByScan).map(([n, s]) => `<td>${statusBadge(s)}</td>`).join('');
        return `<tr><td>${esc(r.type)}</td><td>${esc(r.url)}</td>${statuses}</tr>`;
      }).join('')
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SmartFuzz Report — ${esc(meta.targetDomain)} #${meta.scanNumber}</title>
<style>
  body{font-family:system-ui,sans-serif;background:#0D1117;color:#C9D1D9;margin:0;padding:24px}
  h1,h2{font-family:monospace;color:#3FB950}
  .card{background:#161B22;border:1px solid #30363D;border-radius:8px;padding:16px;margin:16px 0}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{padding:8px 12px;border-bottom:1px solid #21262D;text-align:left}
  th{color:#8B949E;font-weight:600}
  .badge{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;color:#fff}
  .score{font-size:48px;font-weight:700;font-family:monospace}
  .meta{color:#8B949E;font-size:13px}
  .FIXED{color:#3FB950} .NEW{color:#F78166} .VULNERABLE{color:#F85149} .REGRESSED{color:#D29922}
</style>
</head>
<body>
<h1>SmartFuzz Security Report</h1>
<div class="meta">
  Target: <strong>${esc(meta.targetUrl)}</strong> &nbsp;|&nbsp;
  Scan #${meta.scanNumber} &nbsp;|&nbsp;
  ${meta.generatedAt}
</div>

<div class="card">
  <h2>Security Score</h2>
  <div class="score" style="color:${scoreColor(summary.securityScore)}">${summary.securityScore}/100</div>
  <p>${summary.totalVulnerabilities} vulnerabilities:
    ${summary.critical} critical, ${summary.high} high, ${summary.medium} medium,
    ${summary.low} low, ${summary.informational} informational</p>
</div>

<div class="card">
  <h2>Vulnerabilities</h2>
  <table>
    <thead><tr><th>Severity</th><th>Type</th><th>URL</th><th>Parameter</th><th>CVSS</th></tr></thead>
    <tbody>${vulnRows || '<tr><td colspan="5" style="color:#8B949E">No vulnerabilities found</td></tr>'}</tbody>
  </table>
</div>

${comparison.hasPreviousScans ? `
<div class="card">
  <h2>Comparison</h2>
  <p>Fixed: ${comparison.fixed} | New: ${comparison.newlyFound} | Persisting: ${comparison.persisting} | Regressed: ${comparison.regressed}</p>
  <table>
    <thead><tr><th>Type</th><th>URL</th>${Object.keys(comparison.rows[0]?.statusByScan || {}).map((n) => `<th>Scan #${n}</th>`).join('')}</tr></thead>
    <tbody>${compRows}</tbody>
  </table>
</div>` : ''}

<p class="meta">Generated by SmartFuzz — authorized security testing only.</p>
</body>
</html>`;
}

/** CSV export of vulnerabilities. */
export function buildReportCsv(reportJson) {
  const header = 'severity,type,url,param,cvssScore,evidence';
  const rows = reportJson.vulnerabilities.map((v) =>
    [v.severity, v.type, v.url, v.param, v.cvssScore, (v.evidence || '').replace(/,/g, ';')].map(csvEsc).join(','),
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
    `| Severity | Type | URL | Param | CVSS |`,
    `|---|---|---|---|---|`,
    ...vulnerabilities.map((v) => `| ${v.severity} | ${v.type} | ${v.url} | ${v.param} | ${v.cvssScore} |`),
  ];
  return lines.join('\n');
}

// ── helpers ──
function esc(s) { return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
function csvEsc(s) { const str = String(s || ''); return str.includes(',') ? `"${str}"` : str; }
function scoreColor(s) { if (s >= 80) return '#3FB950'; if (s >= 50) return '#D29922'; return '#F85149'; }
function statusBadge(s) { return `<span class="${s}">${s}</span>`; }

/**
 * Build a PDF report buffer using pdfkit (pure-JS, no headless browser).
 * Returns a Promise<Buffer>.
 */
export async function buildReportPdf(reportJson) {
  const PDFDocument = (await import('pdfkit')).default;
  const { meta, summary, vulnerabilities } = reportJson;

  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50, size: 'A4' });
    const chunks = [];
    doc.on('data', (c) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    const SEV_COLORS = {
      critical: '#F85149', high: '#F78166', medium: '#D29922',
      low: '#58A6FF', informational: '#8B949E',
    };

    // ── Title ──
    doc.fontSize(20).fillColor('#3FB950').text('SmartFuzz Security Report', { align: 'left' });
    doc.moveDown(0.3);
    doc.fontSize(10).fillColor('#8B949E')
      .text(`Target: ${meta.targetUrl}`)
      .text(`Scan #${meta.scanNumber}  |  Generated: ${meta.generatedAt}`);
    doc.moveDown(1);

    // ── Score ──
    const scoreClr = summary.securityScore >= 80 ? '#3FB950' : summary.securityScore >= 50 ? '#D29922' : '#F85149';
    doc.fontSize(14).fillColor('#C9D1D9').text('Security Score', { underline: true });
    doc.fontSize(36).fillColor(scoreClr).text(`${summary.securityScore} / 100`);
    doc.fontSize(10).fillColor('#8B949E')
      .text(`${summary.totalVulnerabilities} vulnerabilities: ${summary.critical} critical, ${summary.high} high, ${summary.medium} medium, ${summary.low} low, ${summary.informational} informational`);
    doc.moveDown(1);

    // ── Vulnerability table ──
    doc.fontSize(14).fillColor('#C9D1D9').text('Vulnerabilities', { underline: true });
    doc.moveDown(0.5);

    if (vulnerabilities.length === 0) {
      doc.fontSize(10).fillColor('#8B949E').text('No vulnerabilities found.');
    } else {
      const colWidths = [70, 100, 180, 80, 50];
      const headers = ['Severity', 'Type', 'URL', 'Parameter', 'CVSS'];
      const startX = doc.page.margins.left;
      let y = doc.y;

      // Header row
      doc.fontSize(9).fillColor('#8B949E');
      headers.forEach((h, i) => {
        doc.text(h, startX + colWidths.slice(0, i).reduce((a, b) => a + b, 0), y, { width: colWidths[i], lineBreak: false });
      });
      y += 16;
      doc.moveTo(startX, y).lineTo(startX + colWidths.reduce((a, b) => a + b, 0), y).strokeColor('#30363D').stroke();
      y += 4;

      // Data rows
      for (const v of vulnerabilities.slice(0, 50)) {
        if (y > doc.page.height - 100) { doc.addPage(); y = doc.page.margins.top; }
        const row = [v.severity?.toUpperCase(), v.type, (v.url || '').slice(0, 40), v.param || '', String(v.cvssScore || '')];
        doc.fontSize(8).fillColor(SEV_COLORS[v.severity] || '#C9D1D9');
        doc.text(row[0], startX, y, { width: colWidths[0], lineBreak: false });
        doc.fillColor('#C9D1D9');
        row.slice(1).forEach((cell, i) => {
          doc.text(cell, startX + colWidths.slice(0, i + 1).reduce((a, b) => a + b, 0), y, { width: colWidths[i + 1], lineBreak: false });
        });
        y += 14;
      }
      if (vulnerabilities.length > 50) {
        doc.fontSize(8).fillColor('#8B949E').text(`... and ${vulnerabilities.length - 50} more. See the HTML report for the full list.`, startX, y + 4);
      }
    }

    doc.moveDown(2);
    doc.fontSize(8).fillColor('#8B949E').text('Generated by SmartFuzz — authorized security testing only.', { align: 'center' });

    doc.end();
  });
}
