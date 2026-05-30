import mongoose from 'mongoose';

// Target — a distinct host a user has scanned. Lets us group scans by domain
// for the rescan/comparison feature (PRD §11) and assign per-target scan
// numbers. Unique per (userId, domain).

const targetSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    // Canonical origin (scheme + host[:port]) — what we compare across scans.
    origin: { type: String, required: true, trim: true },
    // Bare host, for display and grouping (e.g. "example.com").
    domain: { type: String, required: true, trim: true, lowercase: true, index: true },
    scanCount: { type: Number, default: 0, min: 0 },
    lastScanAt: { type: Date },
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

// One target row per user per domain.
targetSchema.index({ userId: 1, domain: 1 }, { unique: true });

export const Target = mongoose.models.Target || mongoose.model('Target', targetSchema);
