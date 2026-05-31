import nodemailer from 'nodemailer';
import { config, isTest } from '../config.js';
import { childLogger } from '../logger.js';

// Mailer (PRD §4.4). Three transports:
//   - ethereal: dev default — auto-creates a fake SMTP inbox and logs a preview
//     URL, so no real email account is needed during development.
//   - gmail: production — free Gmail SMTP with an App Password.
//   - json: tests — captures messages in-memory, sends nothing.
//
// The transporter is created lazily and cached. A test seam lets the auth suite
// inject a capture transport and read what "would have been sent".

const log = childLogger('mailer');

let transporter = null;
let override = null;

async function buildTransporter() {
  if (config.MAIL_TRANSPORT === 'json' || isTest()) {
    // Doesn't send; returns the message envelope for inspection.
    return nodemailer.createTransport({ jsonTransport: true });
  }

  if (config.MAIL_TRANSPORT === 'gmail') {
    if (!config.GMAIL_USER || !config.GMAIL_APP_PASSWORD) {
      throw new Error('MAIL_TRANSPORT=gmail requires GMAIL_USER and GMAIL_APP_PASSWORD');
    }
    return nodemailer.createTransport({
      service: 'gmail',
      auth: { user: config.GMAIL_USER, pass: config.GMAIL_APP_PASSWORD },
    });
  }

  // ethereal (default): create a throwaway test account on the fly.
  const account = await nodemailer.createTestAccount();
  log.info({ user: account.user }, 'Ethereal mail account created (dev)');
  return nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    secure: false,
    auth: { user: account.user, pass: account.pass },
  });
}

async function getTransporter() {
  if (override) return override;
  if (!transporter) transporter = await buildTransporter();
  return transporter;
}

/** Inject a transport for tests (e.g. a jsonTransport). Pass null to clear. */
export function setTransporterForTests(fake) {
  override = fake;
  if (fake === null) transporter = null;
}

const otpEmailHtml = (code, ttlMinutes) => `
  <div style="font-family:system-ui,sans-serif;max-width:480px;margin:0 auto;background:#0D1117;color:#C9D1D9;padding:32px;border-radius:12px">
    <h1 style="font-family:monospace;font-size:22px;margin:0 0 8px">Smart<span style="color:#3FB950">Fuzz</span></h1>
    <p style="color:#8B949E;margin:0 0 24px">Your verification code</p>
    <div style="font-family:monospace;font-size:36px;letter-spacing:10px;font-weight:bold;color:#3FB950;background:#010409;padding:16px;border-radius:8px;text-align:center">${code}</div>
    <p style="color:#8B949E;font-size:14px;margin:24px 0 0">This code expires in ${ttlMinutes} minutes. If you didn't request it, ignore this email.</p>
  </div>`;

/**
 * Send the OTP email. Returns { messageId, previewUrl? }. In dev (ethereal) the
 * previewUrl points to a viewable rendering of the sent mail.
 */
export async function sendOtpEmail(email, code) {
  const ttlMinutes = Math.round(config.OTP_TTL_SECONDS / 60);
  const tx = await getTransporter();

  // Gmail SMTP rejects/rewrites a From address that isn't the authenticated
  // account, which can make sends fail. When using the gmail transport, always
  // send from the authenticated Gmail address (with a friendly display name).
  const from =
    config.MAIL_TRANSPORT === 'gmail' && config.GMAIL_USER
      ? `SmartFuzz <${config.GMAIL_USER}>`
      : config.MAIL_FROM;

  const info = await tx.sendMail({
    from,
    to: email,
    subject: `Your SmartFuzz verification code: ${code}`,
    text: `Your SmartFuzz verification code is ${code}. It expires in ${ttlMinutes} minutes.`,
    html: otpEmailHtml(code, ttlMinutes),
  });

  const previewUrl = nodemailer.getTestMessageUrl?.(info) || undefined;
  if (previewUrl) log.info({ previewUrl }, 'OTP email preview (dev)');

  return { messageId: info.messageId, previewUrl };
}
