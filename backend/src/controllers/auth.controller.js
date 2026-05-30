import { z } from 'zod';
import { User } from '@smartfuzz/shared/models';
import { asyncHandler, badRequest, tooManyRequests, unauthorized } from '../middleware/error.middleware.js';
import { createOtp, verifyOtp, isOnCooldown, cooldownRemaining, VERIFY } from '../services/otpStore.js';
import { sendOtpEmail } from '../services/mailer.js';
import { signToken, authCookieOptions, AUTH_COOKIE } from '../lib/jwt.js';
import { config, isProd } from '../config.js';
import { childLogger } from '../logger.js';

const log = childLogger('auth');

// ── Validation schemas ──
const emailSchema = z.object({
  email: z.string().trim().toLowerCase().email('A valid email is required'),
});
const verifySchema = emailSchema.extend({
  otp: z.string().regex(/^\d{6}$/, 'OTP must be 6 digits'),
});

/**
 * POST /api/auth/send-otp
 * Generate an OTP, store it, and email it. Throttled by a resend cooldown.
 * Always responds 200 with a generic message to avoid leaking which emails
 * exist (in dev, also returns the ethereal preview URL for convenience).
 */
export const sendOtp = asyncHandler(async (req, res) => {
  const { email } = emailSchema.parse(req.body);

  if (await isOnCooldown(email)) {
    const retryAfter = await cooldownRemaining(email);
    throw tooManyRequests('Please wait before requesting another code', {
      code: 'OTP_COOLDOWN',
      details: { retryAfterSeconds: retryAfter },
    });
  }

  const code = await createOtp(email);
  const { previewUrl } = await sendOtpEmail(email, code);
  log.info({ email }, 'OTP sent');

  const body = {
    message: 'If that email is valid, a verification code has been sent.',
    expiresInSeconds: config.OTP_TTL_SECONDS,
  };
  // Dev-only conveniences (never in production).
  if (!isProd()) {
    if (previewUrl) body.previewUrl = previewUrl;
    if (config.MAIL_TRANSPORT === 'json') body.devOtp = code;
  }
  res.json(body);
});

/**
 * POST /api/auth/verify-otp
 * Verify the code; on success find-or-create the user, issue a JWT cookie.
 */
export const verifyOtpHandler = asyncHandler(async (req, res) => {
  const { email, otp } = verifySchema.parse(req.body);

  const { result, attemptsLeft } = await verifyOtp(email, otp);

  if (result === VERIFY.NO_OTP) {
    throw badRequest('No active code for this email. Request a new one.', { code: 'OTP_NOT_FOUND' });
  }
  if (result === VERIFY.TOO_MANY_ATTEMPTS) {
    throw tooManyRequests('Too many incorrect attempts. Request a new code.', { code: 'OTP_ATTEMPTS_EXCEEDED' });
  }
  if (result === VERIFY.MISMATCH) {
    throw unauthorized('Incorrect code', { code: 'OTP_MISMATCH', details: { attemptsLeft } });
  }

  // result === OK → find-or-create the user.
  const user = await User.findOneAndUpdate(
    { email },
    { $set: { lastLoginAt: new Date() }, $setOnInsert: { email } },
    { new: true, upsert: true, setDefaultsOnInsert: true },
  );

  const token = signToken(user);
  res.cookie(AUTH_COOKIE, token, authCookieOptions());
  log.info({ email, userId: String(user._id) }, 'User verified');

  res.json({ user: user.toJSON(), token });
});

/** POST /api/auth/logout — clear the auth cookie. */
export const logout = asyncHandler(async (req, res) => {
  res.clearCookie(AUTH_COOKIE, { ...authCookieOptions(), maxAge: undefined });
  res.json({ message: 'Logged out' });
});

/** GET /api/auth/me — current user (requires auth). */
export const me = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) throw unauthorized('User not found', { code: 'USER_NOT_FOUND' });
  res.json({ user: user.toJSON() });
});
