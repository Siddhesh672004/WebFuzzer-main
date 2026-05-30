import mongoose from 'mongoose';

// Endpoint — an attack-surface entry discovered by the crawler: a URL+method
// plus its parameters (each classified by the parameter classifier in Phase 3).
// The baseline response is captured so the response analyzer can diff against
// it (body-size deltas, timing) when fuzzing.

const paramSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    // Where the param lives in the request.
    type: { type: String, enum: ['query', 'body', 'header', 'cookie', 'path'], default: 'query' },
    // HTML input type if known (text/number/email/hidden/…).
    inputType: { type: String, default: 'text' },
    // Classifier output (NUMERIC_ID, SEARCH_FIELD, …) — set in Phase 3.
    category: { type: String, default: 'GENERIC' },
    attackTypes: { type: [String], default: [] },
    // Default/sample value seen during crawl (used as a fuzz baseline).
    sampleValue: { type: String, default: '' },
  },
  { _id: false },
);

const baselineSchema = new mongoose.Schema(
  {
    statusCode: { type: Number },
    bodyLength: { type: Number },
    responseTimeMs: { type: Number },
    contentType: { type: String },
  },
  { _id: false },
);

const endpointSchema = new mongoose.Schema(
  {
    scanId: { type: mongoose.Schema.Types.ObjectId, ref: 'Scan', required: true, index: true },
    url: { type: String, required: true, trim: true },
    method: { type: String, enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD'], default: 'GET' },
    params: { type: [paramSchema], default: [] },
    contentType: { type: String, default: '' },
    // True when discovered inside a <form> (affects how we submit payloads).
    isForm: { type: Boolean, default: false },
    baselineResponse: { type: baselineSchema },
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

// Dedup key: a scan shouldn't store the same url+method twice.
endpointSchema.index({ scanId: 1, url: 1, method: 1 }, { unique: true });

export const Endpoint = mongoose.models.Endpoint || mongoose.model('Endpoint', endpointSchema);
