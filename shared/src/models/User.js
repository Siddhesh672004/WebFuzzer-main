import mongoose from 'mongoose';

// User — identified solely by a verified email (OTP auth, no passwords; PRD §4).
// We deliberately store nothing else sensitive: no password hash, no PII beyond
// the email needed to send the OTP.

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
      match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Invalid email address'],
    },
    lastLoginAt: { type: Date },
    // Monotonic counter used to assign per-user scan numbers cheaply.
    totalScans: { type: Number, default: 0, min: 0 },
  },
  {
    timestamps: true, // createdAt, updatedAt
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

// Re-use an already-compiled model (tests re-import across suites).
export const User = mongoose.models.User || mongoose.model('User', userSchema);
