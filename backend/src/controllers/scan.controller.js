import { z } from 'zod';
import mongoose from 'mongoose';
import { Scan, Target, User, Vulnerability } from '@smartfuzz/shared/models';
import { progressChannel } from '@smartfuzz/shared/progress';
import { asyncHandler, badRequest, notFound, forbidden } from '../middleware/error.middleware.js';
import { enqueueScan } from '../lib/queue.js';
import { getSubscriber } from '../lib/redis.js';
import { config } from '../config.js';
import { childLogger } from '../logger.js';
import { getFixGuide } from '../../../worker/src/knowledge/fixGuides.js';

const log = childLogger('scans');

// Scan controller (PRD §16). Enforces the authorization consent gate
// (IMPLEMENTATION_PLAN §10.3) — a scan cannot start without explicit, logged
// authorization — assigns a per-target scanNumber, enqueues the job, and
// streams live progress over SSE.

const startSchema = z.object({
  targetUrl: z.string().trim().url('A valid http(s) URL is required'),
  authorized: z.literal(true, { errorMap: () => ({ message: 'You must confirm authorization to scan this target' }) }),
  config: z
    .object({
      maxDepth: z.coerce.number().int().min(0).max(10).optional(),
      rateLimit: z.coerce.number().int().min(1).max(100).optional(),
      maxEndpoints: z.coerce.number().int().min(1).max(2000).optional(),
    })
    .optional(),
});

function deriveOrigin(rawUrl) {
  const u = new URL(rawUrl);
  if (!['http:', 'https:'].includes(u.protocol)) throw badRequest('Only http(s) targets are supported');
  return { origin: u.origin, domain: u.hostname.toLowerCase() };
}

/** POST /api/scans — create + enqueue a scan (consent-gated). */
export const createScan = asyncHandler(async (req, res) => {
  const { targetUrl, config: scanCfg } = startSchema.parse(req.body);
  const { origin, domain } = deriveOrigin(targetUrl);
  const userId = req.user.id;

  // Find-or-create the target and atomically bump its scan counter → scanNumber.
  const target = await Target.findOneAndUpdate(
    { userId, domain },
    { $setOnInsert: { userId, origin, domain }, $inc: { scanCount: 1 }, $set: { lastScanAt: new Date() } },
    { new: true, upsert: true, setDefaultsOnInsert: true },
  );
  const scanNumber = target.scanCount;

  const scan = await Scan.create({
    userId,
    targetId: target._id,
    targetUrl,
    targetDomain: domain,
    scanNumber,
    status: 'pending',
    config: {
      maxDepth: scanCfg?.maxDepth ?? config.SCAN_MAX_DEPTH,
      rateLimit: scanCfg?.rateLimit ?? config.SCAN_RATE_LIMIT,
      maxEndpoints: scanCfg?.maxEndpoints ?? config.SCAN_MAX_ENDPOINTS,
      allowPrivate: config.SCAN_ALLOW_PRIVATE,
    },
    consent: {
      authorized: true,
      confirmedAt: new Date(),
      userId,
      ip: req.ip,
      userAgent: req.headers['user-agent'] || '',
    },
  });

  await User.updateOne({ _id: userId }, { $inc: { totalScans: 1 } }).catch(() => {});

  await enqueueScan(scan._id, targetUrl, scan.config.toObject ? scan.config.toObject() : scan.config);
  log.info({ scanId: String(scan._id), domain, scanNumber }, 'scan enqueued');

  res.status(201).json({ scan: scan.toJSON() });
});

/** GET /api/scans — list the user's scans (paginated, newest first). */
export const listScans = asyncHandler(async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = Math.min(50, parseInt(req.query.limit, 10) || 20);
  const filter = { userId: req.user.id };
  const [scans, total] = await Promise.all([
    Scan.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit),
    Scan.countDocuments(filter),
  ]);
  res.json({ scans: scans.map((s) => s.toJSON()), page, limit, total });
});

/** GET /api/scans/:id — scan detail + status. */
export const getScan = asyncHandler(async (req, res) => {
  const scan = await ownedScan(req);
  res.json({ scan: scan.toJSON() });
});

/** GET /api/scans/:id/vulnerabilities — findings for a scan. */
export const getScanVulnerabilities = asyncHandler(async (req, res) => {
  const scan = await ownedScan(req);
  const filter = { scanId: scan._id };

  // Optional filters: severity, type, and fuzzy search on url+param.
  if (req.query.severity && req.query.severity !== 'all') {
    filter.severity = String(req.query.severity);
  }
  if (req.query.type && req.query.type !== 'all') {
    filter.type = String(req.query.type);
  }
  if (req.query.search) {
    const rx = new RegExp(escapeRegex(String(req.query.search)), 'i');
    filter.$or = [{ url: rx }, { param: rx }];
  }

  const vulns = await Vulnerability.find(filter).sort({ cvssScore: -1 });
  res.json({ vulnerabilities: vulns.map((v) => v.toJSON()) });
});

/** GET /api/scans/:id/vulnerabilities/:vulnId — one finding + its fix guide. */
export const getScanVulnerability = asyncHandler(async (req, res) => {
  const scan = await ownedScan(req);
  const { vulnId } = req.params;
  if (!mongoose.isValidObjectId(vulnId)) throw badRequest('Invalid vulnerability id');
  const vuln = await Vulnerability.findOne({ _id: vulnId, scanId: scan._id });
  if (!vuln) throw notFound('Vulnerability not found');
  const out = vuln.toJSON();
  out.fixGuide = getFixGuide(vuln.type);
  res.json({ vulnerability: out });
});

/** GET /api/scans/target/:domain — all scans for a domain (comparison). */
export const getScansByDomain = asyncHandler(async (req, res) => {
  const scans = await Scan.find({ userId: req.user.id, targetDomain: req.params.domain.toLowerCase() }).sort({ scanNumber: 1 });
  res.json({ scans: scans.map((s) => s.toJSON()) });
});

/** DELETE /api/scans/:id — delete a scan + its findings. */
export const deleteScan = asyncHandler(async (req, res) => {
  const scan = await ownedScan(req);
  await Promise.all([Vulnerability.deleteMany({ scanId: scan._id }), Scan.deleteOne({ _id: scan._id })]);
  res.json({ deleted: true });
});

/**
 * GET /api/scans/:id/progress — SSE stream of live progress.
 * Subscribes to the worker's Redis pub/sub channel and forwards events.
 */
export const streamProgress = asyncHandler(async (req, res) => {
  const scan = await ownedScan(req);

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no', // disable proxy buffering (nginx)
  });
  res.write(`event: hello\ndata: ${JSON.stringify({ scanId: String(scan._id), status: scan.status })}\n\n`);

  // If the scan is already terminal, send a snapshot and close.
  if (['completed', 'failed', 'cancelled'].includes(scan.status)) {
    res.write(`event: done\ndata: ${JSON.stringify({ status: scan.status })}\n\n`);
    return res.end();
  }

  const channel = progressChannel(String(scan._id));
  const sub = getSubscriber().duplicate();
  await sub.subscribe(channel);

  const onMessage = (chan, message) => {
    if (chan !== channel) return;
    try {
      const event = JSON.parse(message);
      res.write(`event: ${event.kind}\ndata: ${message}\n\n`);
      if (event.kind === 'done') cleanup();
    } catch {
      /* ignore malformed */
    }
  };
  sub.on('message', onMessage);

  // Heartbeat to keep the connection alive through proxies.
  const heartbeat = setInterval(() => res.write(': ping\n\n'), 15000);

  let closed = false;
  function cleanup() {
    if (closed) return;
    closed = true;
    clearInterval(heartbeat);
    sub.removeListener('message', onMessage);
    sub.unsubscribe(channel).catch(() => {});
    sub.quit().catch(() => sub.disconnect());
    res.end();
  }

  req.on('close', cleanup);
  return undefined;
});

// ── helpers ──
async function ownedScan(req) {
  const { id } = req.params;
  if (!mongoose.isValidObjectId(id)) throw badRequest('Invalid scan id');
  const scan = await Scan.findById(id);
  if (!scan) throw notFound('Scan not found');
  if (String(scan.userId) !== String(req.user.id)) throw forbidden('Not your scan');
  return scan;
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
