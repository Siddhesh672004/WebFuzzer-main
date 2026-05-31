import { Router } from 'express';
import path from 'path';
import fs from 'fs';
import { requireAuth } from '../middleware/auth.middleware.js';
import { config } from '../config.js';

// Screenshot evidence route (Feature 2). Serves the PNG files the worker writes
// to the shared SCREENSHOT_DIR volume. Auth-required; defends against path
// traversal with a strict filename allowlist AND a resolved-path prefix check.

const router = Router();

// GET /api/screenshots/:filename — stream a captured screenshot PNG.
router.get('/screenshots/:filename', requireAuth, (req, res) => {
  const { filename } = req.params;

  // Allowlist: the worker only ever writes `${scanId}_${vulnId}_${ts}.png`.
  // Reject anything with slashes, dot-segments, or a non-.png extension.
  if (!/^[a-zA-Z0-9_-]+\.png$/.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }

  const screenshotDir = path.resolve(config.SCREENSHOT_DIR);
  const filepath = path.resolve(screenshotDir, filename);

  // Belt-and-suspenders: ensure the resolved path stays inside the directory.
  if (filepath !== path.join(screenshotDir, filename) || !filepath.startsWith(screenshotDir + path.sep)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  if (!fs.existsSync(filepath)) {
    return res.status(404).json({ error: 'Screenshot not found' });
  }

  res.setHeader('Content-Type', 'image/png');
  res.setHeader('Cache-Control', 'private, max-age=86400');
  fs.createReadStream(filepath).pipe(res);
});

export default router;
