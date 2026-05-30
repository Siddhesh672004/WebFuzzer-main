import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { requireAuth } from '../middleware/auth.middleware.js';
import { sendOtp, verifyOtpHandler, logout, me } from '../controllers/auth.controller.js';

// Auth routes (PRD §16). The OTP endpoints are extra-sensitive (email abuse,
// brute force), so they carry their own express-rate-limit on top of the
// OTP store's per-email cooldown and attempt cap.

const router = Router();

// Limit OTP requests/verifications per IP to blunt automated abuse. The store's
// per-email cooldown handles the targeted case; this handles the broad case.
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, slow down', code: 'RATE_LIMITED' },
});

router.post('/auth/send-otp', otpLimiter, sendOtp);
router.post('/auth/verify-otp', otpLimiter, verifyOtpHandler);
router.post('/auth/logout', logout);
router.get('/auth/me', requireAuth, me);

export default router;
