import ipaddr from 'ipaddr.js';
import { promises as dns } from 'node:dns';
import { config } from '../config.js';

// SSRF / target guard (IMPLEMENTATION_PLAN §10.1). Nothing makes an outbound
// request until a URL passes here. Rejects non-http(s) schemes and any host
// that resolves to a private/reserved range (loopback, RFC1918, link-local incl.
// the cloud metadata IP, ULA, etc.). Must be re-checked on every redirect hop.
//
// SCAN_ALLOW_PRIVATE=true (off by default) lets us scan local DVWA/WebGoat.

const ALLOWED_SCHEMES = new Set(['http:', 'https:']);

// ipaddr.js range names that are NOT safe to scan (private/reserved).
const BLOCKED_RANGES = new Set([
  'unspecified', // 0.0.0.0 / ::
  'loopback', // 127/8, ::1
  'private', // RFC1918 10/8 172.16/12 192.168/16
  'linkLocal', // 169.254/16 incl. 169.254.169.254, fe80::/10
  'uniqueLocal', // fc00::/7
  'reserved',
  'broadcast',
  'carrierGradeNat', // 100.64/10
]);

export class UrlGuardError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'UrlGuardError';
    this.code = code;
  }
}

/** True if an IP string is in a blocked (private/reserved) range. */
export function isBlockedIp(ip) {
  let addr;
  try {
    addr = ipaddr.process(ip); // unwraps IPv4-mapped IPv6
  } catch {
    return true; // unparseable → treat as unsafe
  }
  const range = addr.range();
  return BLOCKED_RANGES.has(range);
}

/**
 * Validate a target URL. Returns a normalized { url, hostname, addresses } on
 * success; throws UrlGuardError otherwise.
 * @param {string} rawUrl
 * @param {object} [opts] { allowPrivate?: boolean, resolver?: fn }
 */
export async function assertSafeUrl(rawUrl, opts = {}) {
  const allowPrivate = opts.allowPrivate ?? config.SCAN_ALLOW_PRIVATE;

  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new UrlGuardError(`Invalid URL: ${rawUrl}`, 'INVALID_URL');
  }

  if (!ALLOWED_SCHEMES.has(parsed.protocol)) {
    throw new UrlGuardError(`Blocked scheme: ${parsed.protocol}`, 'BLOCKED_SCHEME');
  }

  if (allowPrivate) {
    return { url: parsed.toString(), hostname: parsed.hostname, addresses: [] };
  }

  // If the host is already a literal IP, check it directly.
  if (ipaddr.isValid(parsed.hostname) || isBracketedIpv6(parsed.hostname)) {
    const ip = stripBrackets(parsed.hostname);
    if (isBlockedIp(ip)) {
      throw new UrlGuardError(`Blocked private/reserved IP: ${ip}`, 'BLOCKED_IP');
    }
    return { url: parsed.toString(), hostname: parsed.hostname, addresses: [ip] };
  }

  // Otherwise resolve the hostname and reject if ANY address is blocked.
  const resolver = opts.resolver || defaultResolver;
  let addresses;
  try {
    addresses = await resolver(parsed.hostname);
  } catch {
    throw new UrlGuardError(`DNS resolution failed: ${parsed.hostname}`, 'DNS_FAILED');
  }
  if (!addresses || addresses.length === 0) {
    throw new UrlGuardError(`No addresses for host: ${parsed.hostname}`, 'DNS_EMPTY');
  }
  for (const ip of addresses) {
    if (isBlockedIp(ip)) {
      throw new UrlGuardError(`Host resolves to blocked range: ${ip}`, 'BLOCKED_RESOLVED');
    }
  }

  return { url: parsed.toString(), hostname: parsed.hostname, addresses };
}

function isBracketedIpv6(host) {
  return host.startsWith('[') && host.endsWith(']');
}
function stripBrackets(host) {
  return isBracketedIpv6(host) ? host.slice(1, -1) : host;
}

async function defaultResolver(hostname) {
  const records = await dns.lookup(hostname, { all: true });
  return records.map((r) => r.address);
}

/** Same-origin scope check: is `candidate` on the same host as `base`? */
export function isSameHost(base, candidate) {
  try {
    return new URL(base).host === new URL(candidate, base).host;
  } catch {
    return false;
  }
}
