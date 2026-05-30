import { Router } from 'express';
import { requireAuth } from '../middleware/auth.middleware.js';
import {
  createScan,
  listScans,
  getScan,
  getScanVulnerabilities,
  getScansByDomain,
  deleteScan,
  streamProgress,
} from '../controllers/scan.controller.js';

// Scan routes (PRD §16). All require auth. The SSE progress stream is mounted
// before the generic :id routes so its path resolves cleanly.

const router = Router();

router.post('/scans', requireAuth, createScan);
router.get('/scans', requireAuth, listScans);
router.get('/scans/target/:domain', requireAuth, getScansByDomain);
router.get('/scans/:id/progress', requireAuth, streamProgress);
router.get('/scans/:id/vulnerabilities', requireAuth, getScanVulnerabilities);
router.get('/scans/:id', requireAuth, getScan);
router.delete('/scans/:id', requireAuth, deleteScan);

export default router;
