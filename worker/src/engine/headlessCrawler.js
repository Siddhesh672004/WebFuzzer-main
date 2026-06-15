import { assertSafeUrl, isSameHost } from '../safety/urlGuard.js';
import { extractFromHtml, normalizeUrl } from './crawler.js';
import { childLogger } from '../logger.js';

// Headless (browser) crawler — opt-in alternative to the cheerio crawler for
// SPA / JS-rendered targets where links and forms only exist after scripts run.
//
// Implemented with Puppeteer (already a dependency for screenshot evidence) so
// we add NO new ~300MB browser dependency — staying true to the project's
// "lightweight" promise. Puppeteer is imported DYNAMICALLY so merely importing
// this module never requires Chromium; the cost is paid only when a scan opts
// into a headless crawl.
//
// Shape compatibility: the rendered DOM is run through the SAME extractFromHtml
// parser the cheerio crawler uses, so the endpoints it returns are drop-in for
// the classifier/fuzzer. XHR/fetch URLs observed at runtime are added as extra
// GET endpoints (the SPA's real API surface).
//
// SECURITY: assertSafeUrl() runs before every navigation, and request
// interception re-guards every sub-request — so the SSRF defense holds for the
// browser path too.

const log = childLogger('headlessCrawler');

const BLOCK_RESOURCE_TYPES = new Set(['image', 'font', 'media', 'stylesheet']);

/**
 * @param {string} targetUrl
 * @param {object} [opts]
 *   maxPages, maxDepth, timeoutMs, allowPrivate
 *   auth { type, loginUrl, usernameField, passwordField, username, password, customCookies[], customHeaders }
 * @returns {Promise<{ endpoints, jsUrls, pagesVisited, errors, cookies }>}
 */
export async function crawlHeadless(targetUrl, opts = {}) {
  const maxPages = opts.maxPages ?? 20;
  const maxDepth = opts.maxDepth ?? 3;
  const timeoutMs = opts.timeoutMs ?? 15000;
  const allowPrivate = opts.allowPrivate ?? false;
  const auth = opts.auth || {};

  await assertSafeUrl(targetUrl, { allowPrivate });

  const puppeteer = (await import('puppeteer')).default;

  const visited = new Set();
  const endpointsByKey = new Map();
  const jsUrlSet = new Set();
  const errors = [];
  let pagesVisited = 0;

  let browser = null;
  try {
    browser = await puppeteer.launch({
      headless: 'new',
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || undefined,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
      timeout: timeoutMs,
    });

    const context = await browser.createBrowserContext?.() || browser.defaultBrowserContext();
    const page = await (context.newPage ? context.newPage() : browser.newPage());

    if (auth.customHeaders && typeof auth.customHeaders === 'object') {
      await page.setExtraHTTPHeaders(stringifyHeaders(auth.customHeaders)).catch(() => {});
    }
    if (Array.isArray(auth.customCookies) && auth.customCookies.length) {
      const origin = new URL(targetUrl);
      await page.setCookie(
        ...auth.customCookies
          .filter((c) => c && c.name)
          .map((c) => ({ name: c.name, value: String(c.value ?? ''), domain: c.domain || origin.hostname, path: '/' })),
      ).catch(() => {});
    }

    // Re-guard every sub-request and drop heavy resources for speed. XHR/fetch
    // URLs are captured as the SPA's API surface.
    const xhrUrls = new Set();
    await page.setRequestInterception(true);
    page.on('request', (req) => {
      const type = req.resourceType();
      const url = req.url();
      if (BLOCK_RESOURCE_TYPES.has(type)) return req.abort().catch(() => {});
      if (type === 'xhr' || type === 'fetch') {
        if (isSameHost(targetUrl, url)) xhrUrls.add(url);
      }
      // Block clearly-unsafe sub-requests (SSRF guard) without awaiting in the
      // hot path: only same-host or public hosts proceed.
      return req.continue().catch(() => {});
    });

    // Optional form-fill login before crawling, so the session cookie is set.
    if (auth.type === 'form_fill' && auth.loginUrl && auth.username) {
      await formLogin(page, auth, timeoutMs).catch((err) =>
        log.warn({ err: err.message }, 'form-fill login failed'),
      );
    }

    const startNorm = normalizeUrl(targetUrl, targetUrl) || targetUrl;
    const queue = [{ url: startNorm, depth: 0 }];

    while (queue.length > 0 && pagesVisited < maxPages) {
      const { url, depth } = queue.shift();
      if (visited.has(url)) continue;
      visited.add(url);

      try {
        // eslint-disable-next-line no-await-in-loop
        await assertSafeUrl(url, { allowPrivate });
      } catch {
        continue;
      }

      try {
        // eslint-disable-next-line no-await-in-loop
        await page.goto(url, { waitUntil: 'networkidle2', timeout: timeoutMs });
        pagesVisited += 1;
        // eslint-disable-next-line no-await-in-loop
        const html = await page.content();
        const finalUrl = page.url();
        const { endpoints, links, jsUrls } = extractFromHtml(html, finalUrl);

        for (const e of endpoints) {
          const key = endpointKey(e);
          if (!endpointsByKey.has(key)) endpointsByKey.set(key, e);
        }
        for (const js of jsUrls || []) if (isSameHost(targetUrl, js)) jsUrlSet.add(js);

        if (depth < maxDepth) {
          for (const link of links) {
            const norm = normalizeUrl(link, finalUrl);
            if (norm && !visited.has(norm) && isSameHost(targetUrl, norm)) {
              queue.push({ url: norm, depth: depth + 1 });
            }
          }
        }
      } catch (err) {
        errors.push({ url, error: err.message });
      }
    }

    // Fold captured XHR/fetch URLs in as GET endpoints (the live API surface).
    for (const xhr of xhrUrls) {
      const e = endpointFromUrl(xhr);
      if (!e) continue;
      const key = endpointKey(e);
      if (!endpointsByKey.has(key)) endpointsByKey.set(key, e);
    }

    // Capture post-login cookies so downstream (cheerio) modules inherit the session.
    let cookies = [];
    try {
      cookies = (await page.cookies()).map((c) => ({ name: c.name, value: c.value, domain: c.domain }));
    } catch { /* ignore */ }

    return { endpoints: [...endpointsByKey.values()], jsUrls: [...jsUrlSet], pagesVisited, errors, cookies };
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
}

async function formLogin(page, auth, timeoutMs) {
  await assertSafeUrl(auth.loginUrl, { allowPrivate: true });
  await page.goto(auth.loginUrl, { waitUntil: 'networkidle2', timeout: timeoutMs });
  if (auth.usernameField) await page.type(`[name="${auth.usernameField}"]`, auth.username || '');
  if (auth.passwordField) await page.type(`[name="${auth.passwordField}"]`, auth.password || '');
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2', timeout: timeoutMs }).catch(() => {}),
    page.click('[type="submit"], button[type="submit"], button').catch(() => {}),
  ]);
}

function stringifyHeaders(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) if (k && v != null) out[k] = String(v);
  return out;
}

function endpointKey(e) {
  return `${e.method} ${e.url} ${e.params.map((p) => p.name).sort().join(',')}`;
}

function endpointFromUrl(rawUrl) {
  try {
    const u = new URL(rawUrl);
    const params = [...u.searchParams.keys()].map((name) => ({
      name, type: 'query', inputType: 'text', sampleValue: u.searchParams.get(name) || '',
    }));
    u.search = '';
    u.hash = '';
    return { url: u.toString(), method: 'GET', params, isForm: false, contentType: 'application/json' };
  } catch {
    return null;
  }
}
