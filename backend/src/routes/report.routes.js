import { Router } from 'express';
import { requireAuth } from '../middleware/auth.middleware.js';
import { getReport, getReportJson, getReportHtml, getReportCsv, getReportMarkdown, getReportPdf } from '../controllers/report.controller.js';

const router = Router();

router.get('/reports/:scanId', requireAuth, getReport);
router.get('/reports/:scanId/json', requireAuth, getReportJson);
router.get('/reports/:scanId/html', requireAuth, getReportHtml);
router.get('/reports/:scanId/csv', requireAuth, getReportCsv);
router.get('/reports/:scanId/markdown', requireAuth, getReportMarkdown);
router.get('/reports/:scanId/pdf', requireAuth, getReportPdf);

export default router;
