// @smartfuzz/shared — single source of truth for types, scoring vectors,
// severity bands, and the cross-scan signature. Imported by backend, worker,
// frontend, and tests so these definitions never drift.

export * from './severity.js';
export * from './vulnTypes.js';
export * from './cvssVectors.js';
export * from './signatures.js';
export * from './queues.js';
export * from './progress.js';
