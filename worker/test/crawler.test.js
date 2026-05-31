import { describe, it, expect } from 'vitest';
import { extractFromHtml, normalizeUrl, crawl } from '../src/engine/crawler.js';

// Fake HttpClient: a map of url → { html, contentType }. Lets us test the crawl
// loop deterministically without network (nock would also work; this is faster).
function fakeHttp(pages) {
  return {
    async get(url) {
      const key = url.replace(/\/$/, '');
      const page = pages[key] || pages[url];
      if (!page) return { ok: false, error: 'ENOTFOUND', status: 0, headers: {}, body: '', finalUrl: url };
      return {
        ok: true,
        status: 200,
        headers: { 'content-type': page.contentType || 'text/html' },
        body: page.html,
        finalUrl: url,
      };
    },
  };
}

describe('normalizeUrl', () => {
  it('drops fragments and trailing slash', () => {
    expect(normalizeUrl('https://x.com/a/#frag', 'https://x.com')).toBe('https://x.com/a');
  });
  it('sorts query params for stable dedup', () => {
    expect(normalizeUrl('https://x.com/s?b=2&a=1', 'https://x.com'))
      .toBe(normalizeUrl('https://x.com/s?a=1&b=2', 'https://x.com'));
  });
  it('resolves relative URLs', () => {
    expect(normalizeUrl('/page', 'https://x.com/dir/')).toBe('https://x.com/page');
  });
});

describe('extractFromHtml', () => {
  it('extracts a GET form with inputs', () => {
    const html = `<form action="/search" method="get">
      <input name="q" type="text"><input name="cat" type="hidden" value="all"></form>`;
    const { endpoints } = extractFromHtml(html, 'https://x.com/');
    const form = endpoints.find((e) => e.isForm);
    expect(form.method).toBe('GET');
    expect(form.url).toBe('https://x.com/search');
    expect(form.params.map((p) => p.name).sort()).toEqual(['cat', 'q']);
    expect(form.params.find((p) => p.name === 'cat').inputType).toBe('hidden');
  });

  it('extracts a POST form with body params', () => {
    const html = `<form action="/login" method="post">
      <input name="user"><input name="pass" type="password"></form>`;
    const { endpoints } = extractFromHtml(html, 'https://x.com/');
    const form = endpoints.find((e) => e.isForm);
    expect(form.method).toBe('POST');
    expect(form.params.every((p) => p.type === 'body')).toBe(true);
  });

  it('extracts query params from anchor links', () => {
    const html = `<a href="/item?id=5&ref=home">item</a>`;
    const { endpoints, links } = extractFromHtml(html, 'https://x.com/');
    const ep = endpoints.find((e) => e.url === 'https://x.com/item');
    expect(ep.params.map((p) => p.name).sort()).toEqual(['id', 'ref']);
    expect(links).toContain('https://x.com/item?id=5&ref=home');
  });

  it('captures params on the page URL itself', () => {
    const { endpoints } = extractFromHtml('<html></html>', 'https://x.com/view?page=2');
    expect(endpoints[0].params[0].name).toBe('page');
  });

  it('ignores javascript:, mailto:, and # links', () => {
    const html = `<a href="javascript:void(0)">x</a><a href="mailto:a@b.com">m</a><a href="#top">t</a>`;
    const { links } = extractFromHtml(html, 'https://x.com/');
    expect(links).toHaveLength(0);
  });

  it('collects <script src> URLs as absolute jsUrls', () => {
    const html = `<script src="/static/app.js"></script>
      <script src="https://x.com/bundle.min.js"></script>
      <script>console.log('inline')</script>
      <script src="https://cdn.example.com/lib.js"></script>`;
    const { jsUrls } = extractFromHtml(html, 'https://x.com/');
    expect(jsUrls).toContain('https://x.com/static/app.js');
    expect(jsUrls).toContain('https://x.com/bundle.min.js');
    // Absolute cross-host src is captured here; same-host filtering happens in crawl().
    expect(jsUrls).toContain('https://cdn.example.com/lib.js');
    // Inline scripts (no src) are not collected.
    expect(jsUrls).toHaveLength(3);
  });
});

describe('crawl', () => {
  it('discovers endpoints across linked pages, same-host only', async () => {
    const pages = {
      'https://x.com': { html: '<a href="/search?q=1">s</a><a href="/about">a</a><a href="https://evil.com/x">e</a>' },
      'https://x.com/about': { html: '<form action="/contact" method="post"><input name="msg"></form>' },
      'https://x.com/search': { html: '<html>results</html>' },
    };
    const res = await crawl('https://x.com', fakeHttp(pages), { maxDepth: 2 });
    const urls = res.endpoints.map((e) => e.url);
    expect(urls).toContain('https://x.com/search'); // query param endpoint
    expect(urls).toContain('https://x.com/contact'); // POST form
    // evil.com is off-host → never visited
    expect(res.endpoints.some((e) => e.url.includes('evil.com'))).toBe(false);
  });

  it('respects maxDepth', async () => {
    const pages = {
      'https://x.com': { html: '<a href="/d1">1</a>' },
      'https://x.com/d1': { html: '<a href="/d2?p=1">2</a>' },
      'https://x.com/d2': { html: '<a href="/d3?q=1">3</a>' },
    };
    const res = await crawl('https://x.com', fakeHttp(pages), { maxDepth: 1 });
    // /d1 (depth 1) is visited so its /d2 link becomes an endpoint, but /d2 is
    // never FETCHED (depth 2 > maxDepth), so /d3's endpoint is never discovered.
    expect(res.endpoints.some((e) => e.url === 'https://x.com/d3')).toBe(false);
    expect(res.pagesVisited).toBe(2); // root + /d1 only
  });

  it('respects maxEndpoints cap', async () => {
    const links = Array.from({ length: 20 }, (_, i) => `<a href="/p${i}?x=1">${i}</a>`).join('');
    const pages = { 'https://x.com': { html: links } };
    const res = await crawl('https://x.com', fakeHttp(pages), { maxDepth: 1, maxEndpoints: 5 });
    expect(res.endpoints.length).toBeLessThanOrEqual(5);
  });

  it('records errors for unreachable pages without crashing', async () => {
    const pages = { 'https://x.com': { html: '<a href="/dead">d</a>' } };
    const res = await crawl('https://x.com', fakeHttp(pages), { maxDepth: 1 });
    expect(res.errors.some((e) => e.url.includes('/dead'))).toBe(true);
  });

  it('skips non-HTML content', async () => {
    const pages = {
      'https://x.com': { html: '{"json":true}', contentType: 'application/json' },
    };
    const res = await crawl('https://x.com', fakeHttp(pages), { maxDepth: 1 });
    expect(res.endpoints).toHaveLength(0);
  });

  it('collects same-host JS files and drops cross-host CDN scripts', async () => {
    const pages = {
      'https://x.com': {
        html: `<script src="/static/main.js"></script>
          <script src="https://cdn.example.com/jquery.js"></script>`,
      },
    };
    const res = await crawl('https://x.com', fakeHttp(pages), { maxDepth: 1 });
    expect(res.jsUrls).toContain('https://x.com/static/main.js');
    expect(res.jsUrls.some((u) => u.includes('cdn.example.com'))).toBe(false);
  });
});
