import { verifyToken, AUTH_COOKIE } from '../lib/jwt.js';
import { unauthorized } from './error.middleware.js';

// requireAuth — gate for protected routes. Reads the JWT from the httpOnly
// cookie (preferred) or an Authorization: Bearer header (for API clients/tests),
// verifies it, and attaches { id, email } to req.user. Any failure → 401.

function extractToken(req) {
  // Cookie first (browser flow).
  const cookieToken = req.cookies?.[AUTH_COOKIE];
  if (cookieToken) return cookieToken;
  // Bearer header fallback.
  const header = req.headers.authorization;
  if (header && header.startsWith('Bearer ')) return header.slice(7);
  return null;
}

export function requireAuth(req, res, next) {
  const token = extractToken(req);
  if (!token) return next(unauthorized('Authentication required', { code: 'NO_TOKEN' }));

  try {
    const payload = verifyToken(token);
    req.user = { id: payload.sub, email: payload.email };
    return next();
  } catch (err) {
    const code = err.name === 'TokenExpiredError' ? 'TOKEN_EXPIRED' : 'TOKEN_INVALID';
    return next(unauthorized('Invalid or expired session', { code }));
  }
}

/** Optional auth — attaches req.user if a valid token is present, else continues. */
export function optionalAuth(req, res, next) {
  const token = extractToken(req);
  if (token) {
    try {
      const payload = verifyToken(token);
      req.user = { id: payload.sub, email: payload.email };
    } catch {
      // ignore — treat as anonymous
    }
  }
  return next();
}
