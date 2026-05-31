import path from 'path';
import fs from 'fs/promises';
import { assertSafeUrl } from '../safety/urlGuard.js';
import { config } from '../config.js';
import { childLogger } from '../logger.js';

// Screenshot Evidence Capture (Feature 2). When an XSS / open-redirect finding
// is confirmed, drive a headless Chromium to the proof URL and capture a PNG so
// the UI can show visual evidence the vulnerability actually fires.
//
// This module deliberately uses a real browser (Puppeteer). Puppeteer is
// imported DYNAMICALLY inside captureVulnScreenshot so that:
//   • merely importing this module never requires Chromium to be installed
//     (keeps the default/test build browser-free), and
//   • the cost is only paid when SCAN_SCREENSHOTS is enabled.
//
// SECURITY NOTE: assertSafeUrl() runs first (same SSRF guard the HttpClient
// uses). Puppeteer then navigates that URL with --no-sandbox; this is an
// accepted tradeoff for the screenshot feature and should only be enabled
// against authorized targets.

const log = childLogger('screenshotCapture');

const SCREENSHOT_DIR = config.SCREENSHOT_DIR || process.env.SCREENSHOT_DIR || '/tmp/smartfuzz-screenshots';
const MAX_SCREENSHOT_AGE_DAYS = 7;

async function ensureDir() {
  await fs.mkdir(SCREENSHOT_DIR, { recursive: true }).catch(() => {});
}

/**
 * Capture a screenshot proving a vulnerability fired.
 * @param {object} args
 *   scanId, vulnId  identifiers used in the filename
 *   targetUrl       the proof URL (payload already embedded for xss/redirect)
 *   vulnType        xss | stored_xss | open_redirect | clickjacking
 *   payload?        the payload (for logging only)
 * @returns {Promise<{success:boolean, filename?, filepath?, dialogFired?, dialogMessage?, finalUrl?, error?}>}
 */
export async function captureVulnScreenshot({ scanId, vulnId, targetUrl, vulnType, payload }) {
  // SSRF guard FIRST — never launch a browser at an unsafe target.
  await assertSafeUrl(targetUrl, { allowPrivate: config.SCAN_ALLOW_PRIVATE });
  await ensureDir();

  const puppeteer = (await import('puppeteer')).default;

  let browser = null;
  try {
    browser = await puppeteer.launch({
      headless: 'new',
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || undefined,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--window-size=1280,720',
      ],
      timeout: 15000,
    });

    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 720 });
    page.setDefaultNavigationTimeout(10000);
    page.setDefaultTimeout(10000);

    // Capture any JS dialog (alert/confirm/prompt) — the classic XSS proof.
    let dialogFired = false;
    let dialogMessage = '';
    page.on('dialog', async (dialog) => {
      dialogFired = true;
      dialogMessage = dialog.message();
      await dialog.dismiss().catch(() => {});
    });

    let screenshotUrl = targetUrl;
    if (vulnType === 'clickjacking') {
      const html = generateClickjackingPoC(targetUrl);
      screenshotUrl = `data:text/html,${encodeURIComponent(html)}`;
    }

    try {
      await page.goto(screenshotUrl, { waitUntil: 'networkidle2' });
    } catch {
      // Page may have rendered even if networkidle2 times out — screenshot anyway.
    }

    // Give injected JS a moment to execute (fire dialogs, paint).
    await new Promise((r) => setTimeout(r, 2000));

    const filename = `${scanId}_${vulnId}_${Date.now()}.png`;
    const filepath = path.join(SCREENSHOT_DIR, filename);
    await page.screenshot({ path: filepath, fullPage: false, type: 'png' });

    return { success: true, filename, filepath, dialogFired, dialogMessage, finalUrl: page.url() };
  } catch (error) {
    log.warn({ err: error.message, vulnType, targetUrl }, 'screenshot capture failed');
    return { success: false, error: error.message };
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
}

/** A standalone HTML page that frames the target under a fake button (clickjacking PoC). */
function generateClickjackingPoC(targetUrl) {
  const safe = String(targetUrl).replace(/"/g, '&quot;');
  return `<!DOCTYPE html>
<html>
<head><title>Clickjacking PoC</title>
<style>
  body { background: #1a1a2e; color: white; font-family: monospace; padding: 20px; }
  .frame-wrap { position: relative; width: 800px; height: 500px; }
  iframe { width: 800px; height: 500px; opacity: 0.3; border: 2px solid red; }
  button { position: absolute; top: 200px; left: 300px; z-index: 3;
           padding: 20px 40px; background: red; color: white; font-size: 18px; cursor: pointer; }
</style></head>
<body>
  <h2>Clickjacking PoC — ${safe}</h2>
  <p>Target site is embedded (semi-transparent). A fake button overlays the real UI.</p>
  <div class="frame-wrap">
    <iframe src="${safe}" sandbox="allow-scripts allow-same-origin"></iframe>
    <button>Click here to WIN!</button>
  </div>
</body></html>`;
}

/** Delete screenshots older than MAX_SCREENSHOT_AGE_DAYS. Safe to call on startup. */
export async function cleanupOldScreenshots() {
  try {
    const files = await fs.readdir(SCREENSHOT_DIR);
    const cutoff = Date.now() - MAX_SCREENSHOT_AGE_DAYS * 24 * 60 * 60 * 1000;
    for (const file of files) {
      const filepath = path.join(SCREENSHOT_DIR, file);
      // eslint-disable-next-line no-await-in-loop
      const stat = await fs.stat(filepath).catch(() => null);
      if (stat && stat.mtimeMs < cutoff) {
        // eslint-disable-next-line no-await-in-loop
        await fs.unlink(filepath).catch(() => {});
      }
    }
  } catch {
    // Directory may not exist yet — nothing to clean.
  }
}
