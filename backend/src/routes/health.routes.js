import { Router } from 'express';
import mongoose from 'mongoose';

// Liveness/readiness endpoint. Reports the process status plus the live state
// of the Mongo connection so `docker compose` health checks and the frontend
// can tell when the API is actually usable (not just listening).

const router = Router();

const MONGO_STATES = ['disconnected', 'connected', 'connecting', 'disconnecting'];

router.get('/health', (req, res) => {
  const mongoState = MONGO_STATES[mongoose.connection.readyState] ?? 'unknown';
  const healthy = mongoose.connection.readyState === 1;
  res.status(healthy ? 200 : 503).json({
    status: healthy ? 'ok' : 'degraded',
    service: 'backend',
    uptimeSeconds: Math.round(process.uptime()),
    mongo: mongoState,
    timestamp: new Date().toISOString(),
  });
});

// Lightweight liveness probe that never touches dependencies.
router.get('/ping', (req, res) => {
  res.json({ pong: true });
});

export default router;
