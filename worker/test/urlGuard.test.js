import { describe, it, expect } from 'vitest';
import { assertSafeUrl, isBlockedIp, isSameHost, UrlGuardError } from '../src/safety/urlGuard.js';

// Static resolver stub so tests are deterministic (no real DNS).
const resolveTo = (...ips) => async () => ips;

describe('isBlockedIp', () => {
  it('blocks loopback', () => {
    expect(isBlockedIp('127.0.0.1')).toBe(true);
    expect(isBlockedIp('::1')).toBe(true);
  });
  it('blocks RFC1918 private ranges', () => {
    expect(isBlockedIp('10.0.0.5')).toBe(true);
    expect(isBlockedIp('172.16.4.4')).toBe(true);
    expect(isBlockedIp('192.168.1.1')).toBe(true);
  });
  it('blocks the cloud metadata IP', () => {
    expect(isBlockedIp('169.254.169.254')).toBe(true);
  });
  it('blocks 0.0.0.0 and unique-local IPv6', () => {
    expect(isBlockedIp('0.0.0.0')).toBe(true);
    expect(isBlockedIp('fc00::1')).toBe(true);
  });
  it('allows public IPs', () => {
    expect(isBlockedIp('8.8.8.8')).toBe(false);
    expect(isBlockedIp('1.1.1.1')).toBe(false);
  });
  it('treats unparseable input as unsafe', () => {
    expect(isBlockedIp('not-an-ip')).toBe(true);
  });
});

describe('assertSafeUrl', () => {
  it('rejects non-http(s) schemes', async () => {
    for (const u of ['file:///etc/passwd', 'gopher://x', 'ftp://x']) {
      await expect(assertSafeUrl(u)).rejects.toMatchObject({ code: 'BLOCKED_SCHEME' });
    }
  });

  it('rejects an invalid URL', async () => {
    await expect(assertSafeUrl('not a url')).rejects.toBeInstanceOf(UrlGuardError);
  });

  it('rejects a literal private IP host', async () => {
    await expect(assertSafeUrl('http://127.0.0.1/')).rejects.toMatchObject({ code: 'BLOCKED_IP' });
    await expect(assertSafeUrl('http://169.254.169.254/')).rejects.toMatchObject({ code: 'BLOCKED_IP' });
  });

  it('rejects a host that resolves to a private range', async () => {
    await expect(
      assertSafeUrl('http://evil.example.com/', { resolver: resolveTo('10.0.0.1') }),
    ).rejects.toMatchObject({ code: 'BLOCKED_RESOLVED' });
  });

  it('rejects when ANY resolved address is private (DNS rebinding guard)', async () => {
    await expect(
      assertSafeUrl('http://x.example.com/', { resolver: resolveTo('8.8.8.8', '127.0.0.1') }),
    ).rejects.toMatchObject({ code: 'BLOCKED_RESOLVED' });
  });

  it('allows a public host', async () => {
    const res = await assertSafeUrl('https://example.com/path', { resolver: resolveTo('93.184.216.34') });
    expect(res.hostname).toBe('example.com');
  });

  it('allows private when allowPrivate=true (local testing)', async () => {
    const res = await assertSafeUrl('http://127.0.0.1:8080/', { allowPrivate: true });
    expect(res.hostname).toBe('127.0.0.1');
  });

  it('surfaces a DNS failure as DNS_FAILED', async () => {
    await expect(
      assertSafeUrl('http://nx.example.com/', { resolver: async () => { throw new Error('nxdomain'); } }),
    ).rejects.toMatchObject({ code: 'DNS_FAILED' });
  });
});

describe('isSameHost', () => {
  it('matches same host', () => {
    expect(isSameHost('https://a.com/x', 'https://a.com/y')).toBe(true);
    expect(isSameHost('https://a.com/x', '/relative')).toBe(true);
  });
  it('rejects different host', () => {
    expect(isSameHost('https://a.com', 'https://b.com')).toBe(false);
  });
});
