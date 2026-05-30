import mongoose from 'mongoose';

// Scan — one scan run against a target. Holds config, live progress (driven to
// the UI over SSE), aggregate stats, and the authorization audit record. The
// consent fields are mandatory safety material (IMPLEMENTATION_PLAN §10.3): a
// scan cannot start without an explicit, logged authorization.

const MODULES = ['crawler', 'passive', 'exposed', 'fuzzer', 'auth', 'tech'];

const configSchema = new mongoose.Schema(
  {
    maxDepth: { type: Number, default: 3, min: 0, max: 10 },
    rateLimit: { type: Number, default: 10, min: 1, max: 100 },
    maxEndpoints: { type: Number, default: 500, min: 1 },
    concurrency: { type: Number, default: 5, min: 1, max: 20 },
    modules: { type: [String], enum: MODULES, default: MODULES },
    allowPrivate: { type: Boolean, default: false },
  },
  { _id: false },
);

const progressSchema = new mongoose.Schema(
  {
    endpointsDiscovered: { type: Number, default: 0 },
    payloadsSent: { type: Number, default: 0 },
    vulnerabilitiesFound: { type: Number, default: 0 },
    currentModule: { type: String, default: '' },
    // Per-module lifecycle so the monitor can show each module's state.
    moduleStatus: {
      type: Map,
      of: { type: String, enum: ['pending', 'running', 'completed', 'failed', 'degraded'] },
      default: () => new Map(MODULES.map((m) => [m, 'pending'])),
    },
    percentComplete: { type: Number, default: 0, min: 0, max: 100 },
  },
  { _id: false },
);

const statsSchema = new mongoose.Schema(
  {
    totalEndpoints: { type: Number, default: 0 },
    totalPayloadsSent: { type: Number, default: 0 },
    totalVulnerabilities: { type: Number, default: 0 },
    critical: { type: Number, default: 0 },
    high: { type: Number, default: 0 },
    medium: { type: Number, default: 0 },
    low: { type: Number, default: 0 },
    informational: { type: Number, default: 0 },
    securityScore: { type: Number, default: 100, min: 0, max: 100 },
    startTime: { type: Date },
    endTime: { type: Date },
    durationSeconds: { type: Number, default: 0 },
  },
  { _id: false },
);

const consentSchema = new mongoose.Schema(
  {
    authorized: { type: Boolean, required: true },
    confirmedAt: { type: Date, required: true },
    // Snapshot of who consented, for the audit trail.
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    ip: { type: String },
    userAgent: { type: String },
  },
  { _id: false },
);

const scanSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    targetId: { type: mongoose.Schema.Types.ObjectId, ref: 'Target', index: true },
    targetUrl: { type: String, required: true, trim: true },
    targetDomain: { type: String, required: true, trim: true, lowercase: true, index: true },
    // 1, 2, 3… per target per user — powers the comparison view.
    scanNumber: { type: Number, required: true, min: 1 },
    status: {
      type: String,
      enum: ['pending', 'running', 'completed', 'failed', 'cancelled'],
      default: 'pending',
      index: true,
    },
    error: { type: String },
    config: { type: configSchema, default: () => ({}) },
    progress: { type: progressSchema, default: () => ({}) },
    stats: { type: statsSchema, default: () => ({}) },
    consent: { type: consentSchema, required: true },
  },
  {
    timestamps: true,
    toJSON: {
      transform(_doc, ret) {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
        return ret;
      },
    },
  },
);

// Common query: a user's scans for a domain, newest first.
scanSchema.index({ userId: 1, targetDomain: 1, scanNumber: -1 });

export const SCAN_MODULES = MODULES;
export const Scan = mongoose.models.Scan || mongoose.model('Scan', scanSchema);
