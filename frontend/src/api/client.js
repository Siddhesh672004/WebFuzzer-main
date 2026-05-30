import axios from 'axios';

// Single axios instance for the whole app. `withCredentials` so the httpOnly
// JWT cookie rides along on every request. A response interceptor normalizes
// errors to a consistent shape and surfaces a 401 so the app can redirect to
// the Verify page.

export const api = axios.create({
  baseURL: '/api',
  withCredentials: true,
  timeout: 30_000,
});

// Normalize errors: always reject with { status, message, code, details }.
api.interceptors.response.use(
  (res) => res,
  (error) => {
    const status = error.response?.status ?? 0;
    const data = error.response?.data ?? {};
    const normalized = {
      status,
      message: data.error || error.message || 'Request failed',
      code: data.code,
      details: data.details,
    };
    return Promise.reject(normalized);
  },
);

// Auth API surface (implemented server-side in Phase 1).
export const authApi = {
  sendOtp: (email) => api.post('/auth/send-otp', { email }).then((r) => r.data),
  verifyOtp: (email, otp) => api.post('/auth/verify-otp', { email, otp }).then((r) => r.data),
  logout: () => api.post('/auth/logout').then((r) => r.data),
  me: () => api.get('/auth/me').then((r) => r.data),
};

// Health (used by the skeleton smoke test and a future status indicator).
export const systemApi = {
  health: () => api.get('/health').then((r) => r.data),
};
