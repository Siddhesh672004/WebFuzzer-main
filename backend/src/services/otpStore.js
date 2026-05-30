import bcrypt from 'bcryptjs';
import { randomInt } from 'node:crypto';
import { getRedis } from '../lib/redis.js';
import { config } from '../config.js';

// OTP storage layer (PRD §4.2). A 6-digit code is generated, bcrypt-hashed, and
// stored in Redis under otp:{email} with a TTL. The plaintext code is returned
// once (to the mailer) and never persisted. Verification compares against the
// hash, tracks attempts, and consumes the OTP on success or attempt-exhaustion.
//
// Keys:
//   otp:{email}            → JSON { hash, attempts }  (TTL = OTP_TTL_SECONDS)
//   otp:cooldown:{email}   → "1"                      (TTL = resend cooldown)

const otpKey = (email) => `otp:${email.toLowerCase()}`;
const cooldownKey = (email) => `otp:cooldown:${email.toLowerCase()}`;

/** Generate a cryptographically-random 6-digit code (leading zeros allowed). */
export function generateOtp() {
  return String(randomInt(0, 1_000_000)).padStart(6, '0');
}

/** True if the email is still within its resend cooldown window. */
export async function isOnCooldown(email) {
  const ttl = await getRedis().ttl(cooldownKey(email));
  return ttl > 0;
}

/** Seconds remaining on the resend cooldown (0 if none). */
export async function cooldownRemaining(email) {
  const ttl = await getRedis().ttl(cooldownKey(email));
  return ttl > 0 ? ttl : 0;
}

/**
 * Create and store a new OTP for an email. Returns the plaintext code so the
 * caller can email it. Sets the resend cooldown. Overwrites any existing OTP.
 */
export async function createOtp(email) {
  const redis = getRedis();
  const code = generateOtp();
  const hash = await bcrypt.hash(code, 10);
  const payload = JSON.stringify({ hash, attempts: 0 });

  await redis.set(otpKey(email), payload, 'EX', config.OTP_TTL_SECONDS);
  await redis.set(cooldownKey(email), '1', 'EX', config.OTP_RESEND_COOLDOWN_SECONDS);

  return code;
}

// Verification outcomes.
export const VERIFY = Object.freeze({
  OK: 'ok',
  NO_OTP: 'no_otp', // never sent or expired
  MISMATCH: 'mismatch', // wrong code, attempts remain
  TOO_MANY_ATTEMPTS: 'too_many_attempts', // exhausted; OTP consumed
});

/**
 * Verify a submitted code against the stored OTP.
 * @returns {Promise<{result: string, attemptsLeft?: number}>}
 */
export async function verifyOtp(email, submittedCode) {
  const redis = getRedis();
  const key = otpKey(email);
  const raw = await redis.get(key);
  if (!raw) return { result: VERIFY.NO_OTP };

  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    await redis.del(key);
    return { result: VERIFY.NO_OTP };
  }

  const matches = await bcrypt.compare(String(submittedCode), data.hash);
  if (matches) {
    await redis.del(key); // single-use
    return { result: VERIFY.OK };
  }

  const attempts = (data.attempts ?? 0) + 1;
  const remaining = config.OTP_MAX_ATTEMPTS - attempts;

  if (remaining <= 0) {
    await redis.del(key); // exhausted — force a fresh request
    return { result: VERIFY.TOO_MANY_ATTEMPTS, attemptsLeft: 0 };
  }

  // Persist the incremented attempt count without extending the TTL.
  const ttl = await redis.ttl(key);
  await redis.set(key, JSON.stringify({ ...data, attempts }), 'EX', ttl > 0 ? ttl : config.OTP_TTL_SECONDS);
  return { result: VERIFY.MISMATCH, attemptsLeft: remaining };
}

/** Remove any OTP/cooldown for an email (used in tests/cleanup). */
export async function clearOtp(email) {
  const redis = getRedis();
  await redis.del(otpKey(email));
  await redis.del(cooldownKey(email));
}
