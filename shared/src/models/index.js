// @smartfuzz/shared/models — Mongoose models shared by backend (reads/writes)
// and worker (writes findings). Defined once here so the schema is a single
// contract with no drift. Imported via the "./models" subpath so the frontend
// (which only needs severity/types) never pulls in mongoose.

export { User } from './User.js';
export { Target } from './Target.js';
export { Scan, SCAN_MODULES } from './Scan.js';
export { Endpoint } from './Endpoint.js';
export { Vulnerability } from './Vulnerability.js';
export { Payload } from './Payload.js';
export { Report } from './Report.js';
