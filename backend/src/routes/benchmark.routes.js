import { Router } from 'express';
import { requireAuth } from '../middleware/auth.middleware.js';
import { getBenchmarkStats, getMeta } from '../controllers/benchmark.controller.js';

const router = Router();

// Aggregate benchmark metrics for the signed-in user.
router.get('/benchmark/stats', requireAuth, getBenchmarkStats);
// Public runtime flags (demo mode) — read by the frontend before/around scan setup.
router.get('/meta', getMeta);

export default router;
