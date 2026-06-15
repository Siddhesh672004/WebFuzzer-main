import { api } from './client.js';

// Scan API surface wired to the backend routes built in Phase 2.

export const scanApi = {
  create: (targetUrl, authorized = true, config = {}) =>
    api.post('/scans', { targetUrl, authorized, config }).then((r) => r.data),

  list: (page = 1, limit = 20) =>
    api.get('/scans', { params: { page, limit } }).then((r) => r.data),

  get: (id) => api.get(`/scans/${id}`).then((r) => r.data),

  delete: (id) => api.delete(`/scans/${id}`).then((r) => r.data),

  vulnerabilities: (id, params = {}) =>
    api.get(`/scans/${id}/vulnerabilities`, { params }).then((r) => r.data),

  vulnerability: (id, vulnId) =>
    api.get(`/scans/${id}/vulnerabilities/${vulnId}`).then((r) => r.data),

  byDomain: (domain) =>
    api.get(`/scans/target/${encodeURIComponent(domain)}`).then((r) => r.data),
};

// Benchmark metrics (P4.4) + public runtime flags (demo mode, P6.2).
export const benchmarkApi = {
  stats: () => api.get('/benchmark/stats').then((r) => r.data),
};
export const metaApi = {
  get: () => api.get('/meta').then((r) => r.data),
};

// Report cache invalidation (P0.2) — drop the cached report so the next view rebuilds.
export const reportAdminApi = {
  invalidate: (scanId) => api.delete(`/reports/${scanId}`).then((r) => r.data),
};

// Remediation tracker (Phase 6).
export const vulnApi = {
  markFixed: (vulnId, fixed = true) =>
    api.post(`/vulnerabilities/${vulnId}/mark-fixed`, { fixed }).then((r) => r.data),
  verify: (vulnId) =>
    api.post(`/vulnerabilities/${vulnId}/verify`).then((r) => r.data),
};

// Report downloads. Each returns a Blob for client-side save.
export const reportApi = {
  get: (scanId) => api.get(`/reports/${scanId}`).then((r) => r.data),
  download: (scanId, format) =>
    api.get(`/reports/${scanId}/${format}`, { responseType: 'blob' }).then((r) => r.data),
  downloadHtml: (scanId) =>
    api.get(`/reports/${scanId}/html`, { responseType: 'blob' }).then((r) => r.data),
  downloadCsv: (scanId) =>
    api.get(`/reports/${scanId}/csv`, { responseType: 'blob' }).then((r) => r.data),
};

/** Trigger a browser download of a Blob with a given filename. */
export function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
