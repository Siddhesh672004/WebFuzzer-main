// Authenticated-crawl helpers. Turns a scan's auth config into the request
// headers the shared HttpClient (and every engine module that uses it) should
// carry, so cookie/header auth applies uniformly across the whole scan. The
// form_fill flow is handled separately by the headless crawler, which captures
// the post-login session cookies and feeds them back through here.

/**
 * Build the static auth headers (Cookie + custom headers) from an auth config.
 * Safe on any shape — returns {} when nothing is configured.
 * @param {object} auth { customCookies[], customHeaders }
 * @returns {Record<string,string>}
 */
export function buildAuthHeaders(auth = {}) {
  const headers = {};
  if (Array.isArray(auth.customCookies) && auth.customCookies.length > 0) {
    const cookie = auth.customCookies
      .filter((c) => c && c.name)
      .map((c) => `${c.name}=${c.value ?? ''}`)
      .join('; ');
    if (cookie) headers.Cookie = cookie;
  }
  if (auth.customHeaders && typeof auth.customHeaders === 'object') {
    for (const [k, v] of Object.entries(auth.customHeaders)) {
      if (k && v != null) headers[k] = String(v);
    }
  }
  return headers;
}

/** Serialize an array of {name,value} cookies (e.g. from a browser context) into a Cookie header. */
export function cookiesToHeader(cookies = []) {
  return cookies
    .filter((c) => c && c.name)
    .map((c) => `${c.name}=${c.value ?? ''}`)
    .join('; ');
}
