import jwt from 'jsonwebtoken';
import { config } from '../config.js';

// JWT helpers (PRD §4.5). Tokens carry the user id + email, are signed with
// JWT_SECRET, and expire per JWT_EXPIRES_IN (default 7d). The token rides in an
// httpOnly + SameSite=Strict cookie so client JS can't read it (XSS-safe) and
// it isn't sent cross-site (CSRF-safe).

/** Sign a JWT for a verified user. */
export function signToken(user) {
  const payload = { sub: String(user._id ?? user.id), email: user.email };
  return jwt.sign(payload, config.JWT_SECRET, { expiresIn: config.JWT_EXPIRES_IN });
}

/** Verify a token; throws on invalid/expired/tampered. Returns the payload. */
export function verifyToken(token) {
  return jwt.verify(token, config.JWT_SECRET);
}

// Cookie options for the auth token. Secure in production (HTTPS); SameSite
// Strict everywhere. maxAge mirrors the 7-day token lifetime.
export function authCookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'strict',
    secure: config.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/',
  };
}

export const AUTH_COOKIE = config.AUTH_COOKIE_NAME;
