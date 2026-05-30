import mongoose from 'mongoose';
import { SEVERITY_ORDER } from '../severity.js';

// Report — a generated, persisted snapshot of a completed scan (PRD §12). Holds
// the executive summary, the comparison roll-up vs prior scans, and the rendered
// artifacts. We store the JSON structure inline; large binary formats (PDF) are
// generated on demand from this data rather than stored as blobs.

const summarySchema = new mongoose.Schema(
  {
    critical: { type: Number, default: 0 },
    high: { type: Number, default: 0 },
    medium: { type: Number, default: 0 },
    low: { type: Number, default: 0 },
    informational: { type: Number, default: 0 },
    securityScore: { type: Number, default: 100, min: 0, max: 100 },
    totalVulnerabilities: { type: Number, default: 0 },
  },
  { _id: false },
);

const comparisonSchema = new mongoose.Schema(
  {
    hasPreviousScans: { type: Boolean, default: false },
    previousScanIds: { type: [mongoose.Schema.Types.ObjectId], default: [] },
    fixed: { type: Number, default: 0 },
    newlyFound: { type: Number, default: 0 },
    persisting: { type: Number, default: 0 },
    regressed: { type: Number, default: 0 },
  },
  { _id: false },
);

const reportSchema = new mongoose.Schema(
  {
    scanId: { type: mongoose.Schema.Types.ObjectId, ref: 'Scan', required: true, unique: true, index: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    targetUrl: { type: String, required: true },
    targetDomain: { type: String, required: true, lowercase: true, index: true },
    scanNumber: { type: Number, required: true },
    generatedAt: { type: Date, default: Date.now },
    summary: { type: summarySchema, default: () => ({}) },
    comparison: { type: comparisonSchema, default: () => ({}) },
    // Top findings by severity for the executive summary (denormalized).
    topFindings: {
      type: [
        new mongoose.Schema(
          {
            type: String,
            severity: { type: String, enum: SEVERITY_ORDER },
            cvssScore: Number,
            url: String,
            param: String,
          },
          { _id: false },
        ),
      ],
      default: [],
    },
    // Full structured data used to render any output format on demand.
    jsonContent: { type: mongoose.Schema.Types.Mixed, default: {} },
    // Pre-rendered standalone HTML (single-file, embedded CSS).
    htmlContent: { type: String, default: '' },
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

export const Report = mongoose.models.Report || mongoose.model('Report', reportSchema);
