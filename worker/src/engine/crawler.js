import * as cheerio from 'cheerio';
import { isSameHost } from '../safety/urlGuard.js';

// Crawler (PRD §9.2). BFS over a target's same-host pages up to a depth/endpoint
// cap. Extracts forms (+inputs), anchor links, and query-string params. Pure
// parsing is split out (extractFromHtml) so it's unit-testable without network;
// the crawl loop uses an injected HttpClient so tests drive it with nock.

/** Normalize a URL for dedup: drop fragment, sort query keys, strip trailing /. */
export function normalizeUrl(raw, base) {
  let u;
  try {
    u = new URL(raw, base);
  } catch {
    return null;
  }
  u.hash = '';
  // Sort query params for stable dedup.
  const params = [...u.searchParams.entries()].sort(([a], [b]) => a.localeCompare(b));
  u.search = '';
  for (const [k, v] of params) u.searchParams.append(k, v);
  let s = u.toString();
  if (s.endsWith('/') && u.pathname !== '/') s = s.slice(0, -1);
  return s;
}

/**
 * Extract endpoints + links from an HTML document.
 * @returns {{ endpoints: Endpoint[], links: string[] }}
 */
export function extractFromHtml(html, pageUrl) {
  const $ = cheerio.load(html);
  const endpoints = [];
  const links = new Set();

  // 1. Query params already present on the page URL itself.
  const pageParams = paramsFromUrl(pageUrl);
  if (pageParams.length > 0) {
    endpoints.push({
      url: stripQuery(pageUrl),
      method: 'GET',
      params: pageParams,
      isForm: false,
      contentType: 'text/html',
    });
  }

  // 2. Forms.
  $('form').each((_, el) => {
    const $form = $(el);
    const action = $form.attr('action') ?? '';
    const method = ($form.attr('method') || 'GET').toUpperCase();
    let actionUrl;
    try {
      actionUrl = new URL(action || pageUrl, pageUrl).toString();
    } catch {
      return;
    }
    const params = [];
    $form.find('input, textarea, select').each((__, input) => {
      const $i = $(input);
      const name = $i.attr('name');
      if (!name) return;
      params.push({
        name,
        type: method === 'GET' ? 'query' : 'body',
        inputType: ($i.attr('type') || (input.tagName === 'textarea' ? 'textarea' : 'text')).toLowerCase(),
        sampleValue: $i.attr('value') || '',
      });
    });
    endpoints.push({
      url: stripQuery(actionUrl),
      method: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].includes(method) ? method : 'GET',
      params,
      isForm: true,
      contentType: 'application/x-www-form-urlencoded',
    });
  });

  // 3. Anchor links (for crawl frontier) + any query params they carry.
  $('a[href]').each((_, el) => {
    const href = $(el).attr('href');
    if (!href || href.startsWith('javascript:') || href.startsWith('mailto:') || href.startsWith('#')) return;
    let abs;
    try {
      abs = new URL(href, pageUrl).toString();
    } catch {
      return;
    }
    links.add(abs);
    const lp = paramsFromUrl(abs);
    if (lp.length > 0) {
      endpoints.push({ url: stripQuery(abs), method: 'GET', params: lp, isForm: false, contentType: 'text/html' });
    }
  });

  return { endpoints, links: [...links] };
}

function paramsFromUrl(url) {
  try {
    const u = new URL(url);
    return [...u.searchParams.keys()].map((name) => ({
      name,
      type: 'query',
      inputType: 'text',
      sampleValue: u.searchParams.get(name) || '',
    }));
  } catch {
    return [];
  }
}

function stripQuery(url) {
  try {
    const u = new URL(url);
    u.search = '';
    u.hash = '';
    return u.toString();
  } catch {
    return url;
  }
}

/** Endpoint dedup key. */
function endpointKey(e) {
  return `${e.method} ${e.url} ${e.params.map((p) => p.name).sort().join(',')}`;
}

/**
 * Crawl a target. BFS, same-host only, depth- and count-capped.
 * @param {string} targetUrl
 * @param {HttpClient} http
 * @param {object} [opts] { maxDepth, maxEndpoints, onProgress }
 * @returns {Promise<{ endpoints, pagesVisited, errors }>}
 */
export async function crawl(targetUrl, http, opts = {}) {
  const maxDepth = opts.maxDepth ?? 3;
  const maxEndpoints = opts.maxEndpoints ?? 500;
  const onProgress = opts.onProgress || (() => {});

  const visited = new Set();
  const endpointsByKey = new Map();
  const errors = [];
  let pagesVisited = 0;

  const startNorm = normalizeUrl(targetUrl, targetUrl);
  const queue = [{ url: startNorm || targetUrl, depth: 0 }];

  while (queue.length > 0 && endpointsByKey.size < maxEndpoints) {
    const { url, depth } = queue.shift();
    if (visited.has(url)) continue;
    visited.add(url);

    // eslint-disable-next-line no-await-in-loop
    const res = await http.get(url);
    pagesVisited += 1;
    if (!res.ok) {
      errors.push({ url, error: res.error });
      continue;
    }

    const contentType = String(res.headers['content-type'] || '');
    if (!contentType.includes('html')) continue; // only parse HTML

    const { endpoints, links } = extractFromHtml(res.body, res.finalUrl || url);
    for (const e of endpoints) {
      const key = endpointKey(e);
      if (!endpointsByKey.has(key)) {
        endpointsByKey.set(key, e);
        onProgress({ endpointsDiscovered: endpointsByKey.size });
        if (endpointsByKey.size >= maxEndpoints) break;
      }
    }

    if (depth < maxDepth) {
      for (const link of links) {
        const norm = normalizeUrl(link, url);
        if (norm && !visited.has(norm) && isSameHost(targetUrl, norm)) {
          queue.push({ url: norm, depth: depth + 1 });
        }
      }
    }
  }

  return { endpoints: [...endpointsByKey.values()], pagesVisited, errors };
}
