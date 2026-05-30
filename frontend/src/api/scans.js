import { api } from './client.js';

// Scan API surface wired to the backend routes built in Phase 2.

export const scanApi = {
  create: (targetUrl, authorized = true, config = {}) =>
    api.post('/scans', { targetUrl, authorized, config }).then((r) => r.data),

  list: (page = 1, limit = 20) =>
    api.get('/scans', { params: { page, limit } }).then((r) => r.data),

  get: (id) => api.get(`/scans/${id}`).then((r) => r.data),

  delete: (id) => api.delete(`/scans/${id}`).then((r) => r.data),

  vulnerabilities: (id) =>
    api.get(`/scans/${id}/vulnerabilities`).then((r) => r.data),

  byDomain: (domain) =>
    api.get(`/scans/target/${encodeURIComponent(domain)}`).then((r) => r.data),
};

export const reportApi = {
  get: (scanId) => api.get(`/reports/${scanId}`).then((r) => r.data),
  downloadHtml: (scanId) =>
    api.get(`/reports/${scanId}/html`, { responseType: 'blob' }).then((r) => r.data),
  downloadCsv: (scanId) =>
    api.get(`/reports/${scanId}/csv`, { responseType: 'blob' }).then((r) => r.data),
};
