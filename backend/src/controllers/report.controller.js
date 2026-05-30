import mongoose from 'mongoose';
import { Scan, Vulnerability, Report } from '@smartfuzz/shared/models';
import { asyncHandler, notFound, forbidden, badRequest } from '../middleware/error.middleware.js';
import { buildReportJson, buildReportHtml, buildReportCsv, buildReportMarkdown } from '../../../worker/src/scoring/reportGenerator.js';

// Report controller — generates and caches reports for completed scans.
// The report is built on first request and stored in the Report collection.

async function getOrBuildReport(scanId, userId) {
  if (!mongoose.isValidObjectId(scanId)) throw badRequest('Invalid scan id');
  const scan = await Scan.findById(scanId);
  if (!scan) throw notFound('Scan not found');
  if (String(scan.userId) !== String(userId)) throw forbidden('Not your scan');
  if (scan.status !== 'completed') throw badRequest('Scan is not yet completed');

  // Return cached report if available.
  let report = await Report.findOne({ scanId: scan._id });
  if (report) return { scan, report };

  // Build fresh.
  const vulns = await Vulnerability.find({ scanId: scan._id }).lean();
  const priorScans = await Scan.find({
    userId: scan.userId,
    targetDomain: scan.targetDomain,
    scanNumber: { $lt: scan.scanNumber },
    status: 'completed',
  }).lean();

  const priorData = await Promise.all(
    priorScans.map(async (ps) => ({
      scanId: ps._id,
      scanNumber: ps.scanNumber,
      vulnerabilities: await Vulnerability.find({ scanId: ps._id }).lean(),
    })),
  );

  const json = buildReportJson(scan.toObject(), vulns, priorData);
  const html = buildReportHtml(json);

  report = await Report.create({
    scanId: scan._id,
    userId: scan.userId,
    targetUrl: scan.targetUrl,
    targetDomain: scan.targetDomain,
    scanNumber: scan.scanNumber,
    summary: json.summary,
    comparison: {
      hasPreviousScans: json.comparison.hasPreviousScans,
      fixed: json.comparison.fixed || 0,
      newlyFound: json.comparison.newlyFound || 0,
      persisting: json.comparison.persisting || 0,
      regressed: json.comparison.regressed || 0,
    },
    jsonContent: json,
    htmlContent: html,
  });

  return { scan, report };
}

export const getReport = asyncHandler(async (req, res) => {
  const { report } = await getOrBuildReport(req.params.scanId, req.user.id);
  res.json({ report: report.toJSON() });
});

export const getReportHtml = asyncHandler(async (req, res) => {
  const { scan, report } = await getOrBuildReport(req.params.scanId, req.user.id);
  const filename = `SmartFuzz_Report_${scan.targetDomain}_Scan${scan.scanNumber}_${new Date().toISOString().slice(0, 10)}.html`;
  res.setHeader('Content-Type', 'text/html');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(report.htmlContent);
});

export const getReportCsv = asyncHandler(async (req, res) => {
  const { scan, report } = await getOrBuildReport(req.params.scanId, req.user.id);
  const csv = buildReportCsv(report.jsonContent);
  const filename = `SmartFuzz_Report_${scan.targetDomain}_Scan${scan.scanNumber}.csv`;
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(csv);
});

export const getReportMarkdown = asyncHandler(async (req, res) => {
  const { scan, report } = await getOrBuildReport(req.params.scanId, req.user.id);
  const md = buildReportMarkdown(report.jsonContent);
  const filename = `SmartFuzz_Report_${scan.targetDomain}_Scan${scan.scanNumber}.md`;
  res.setHeader('Content-Type', 'text/markdown');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(md);
});
