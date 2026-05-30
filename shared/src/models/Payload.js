import mongoose from 'mongoose';
import { VULN_TYPE_KEYS } from '../vulnTypes.js';

// Payload — the seeded attack library (PRD §8, §15). Populated once from the
// cloned wordlists (SecLists / PayloadsAllTheThings / FuzzDB) by payloads/seed.js.
// `successCount` is bumped when a payload confirms a finding, enabling the
// "prioritize historically effective payloads" behavior of the payload engine.

const payloadSchema = new mongoose.Schema(
  {
    source: {
      type: String,
      enum: ['seclists', 'payloadsallthethings', 'fuzzdb', 'nikto', 'custom'],
      required: true,
      index: true,
    },
    type: { type: String, required: true, enum: VULN_TYPE_KEYS, index: true },
    value: { type: String, required: true },
    // Parameter categories this payload is well-suited to (NUMERIC_ID, …).
    categories: { type: [String], default: [] },
    successCount: { type: Number, default: 0, min: 0, index: true },
    tags: { type: [String], default: [] },
    isActive: { type: Boolean, default: true },
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

// Idempotent seeding: a (type, value) pair is unique, so re-running the seed
// script updates rather than duplicates.
payloadSchema.index({ type: 1, value: 1 }, { unique: true });
// Engine query: active payloads of a type, best-performing first.
payloadSchema.index({ type: 1, isActive: 1, successCount: -1 });

export const Payload = mongoose.models.Payload || mongoose.model('Payload', payloadSchema);
