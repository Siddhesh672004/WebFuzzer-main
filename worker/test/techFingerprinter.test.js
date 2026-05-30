import { describe, it, expect } from 'vitest';
import { fingerprint } from '../src/engine/techFingerprinter.js';
import { compareVersions, matchCves } from '../src/knowledge/cveDatabase.js';

const techNames = (r) => r.technologies.map((t) => t.tech);
const findingTypes = (r) => r.findings.map((f) => `${f.type}${f.cveId ? ':' + f.cveId : ''}`);

describe('compareVersions', () => {
  it('orders versions correctly', () => {
    expect(compareVersions('1.0.0', '1.0.1')).toBe(-1);
    expect(compareVersions('2.0', '1.9.9')).toBe(1);
    expect(compareVersions('3.4.1', '3.4.1')).toBe(0);
  });
  it('handles differing segment counts', () => {
    expect(compareVersions('1.2', '1.2.0')).toBe(0);
    expect(compareVersions('1.2.3', '1.2')).toBe(1);
  });
});

describe('matchCves', () => {
  it('matches a vulnerable version', () => {
    const cves = matchCves('jquery', '3.4.1');
    expect(cves.some((c) => c.cve === 'CVE-2020-11022')).toBe(true);
  });
  it('does not match a patched version', () => {
    expect(matchCves('jquery', '3.5.0')).toHaveLength(0);
  });
  it('returns [] for unknown tech or missing version', () => {
    expect(matchCves('unknownlib', '1.0')).toHaveLength(0);
    expect(matchCves('jquery', '')).toHaveLength(0);
  });
});

describe('fingerprint — headers', () => {
  it('detects Server with version', () => {
    const r = fingerprint({ url: 'https://x.com', headers: { server: 'Apache/2.4.49' }, body: '' });
    expect(techNames(r)).toContain('apache');
    // Apache 2.4.49 → CVE-2021-41773
    expect(findingTypes(r)).toContain('known_cve:CVE-2021-41773');
  });

  it('detects X-Powered-By', () => {
    const r = fingerprint({ url: 'https://x.com', headers: { 'x-powered-by': 'PHP/5.6.40' }, body: '' });
    expect(techNames(r)).toContain('php');
    expect(findingTypes(r)).toContain('known_cve:CVE-2019-11043');
  });
});

describe('fingerprint — cookies & meta', () => {
  it('detects PHP via PHPSESSID cookie', () => {
    const r = fingerprint({ url: 'https://x.com', headers: { 'set-cookie': 'PHPSESSID=abc; path=/' }, body: '' });
    expect(techNames(r)).toContain('php');
  });

  it('detects WordPress via meta generator with version', () => {
    const body = '<meta name="generator" content="WordPress 5.8.1">';
    const r = fingerprint({ url: 'https://x.com', headers: {}, body });
    expect(techNames(r)).toContain('wordpress');
    expect(findingTypes(r)).toContain('known_cve:CVE-2022-21661');
  });
});

describe('fingerprint — body patterns', () => {
  it('detects WordPress via wp-content path', () => {
    const r = fingerprint({ url: 'https://x.com', headers: {}, body: '<link href="/wp-content/themes/x/style.css">' });
    expect(techNames(r)).toContain('wordpress');
  });

  it('detects a JS library version and matches CVE', () => {
    const r = fingerprint({ url: 'https://x.com', headers: {}, body: '<script src="/assets/jquery-3.4.1.min.js"></script>' });
    expect(techNames(r)).toContain('jquery');
    expect(findingTypes(r)).toContain('known_cve:CVE-2020-11022');
  });

  it('does not raise a CVE for a patched JS library', () => {
    const r = fingerprint({ url: 'https://x.com', headers: {}, body: '<script src="/assets/jquery-3.6.0.min.js"></script>' });
    expect(techNames(r)).toContain('jquery');
    expect(r.findings.some((f) => f.type === 'known_cve')).toBe(false);
  });
});

describe('fingerprint — finding shape', () => {
  it('emits informational tech_fingerprint findings (cvss 0)', () => {
    const r = fingerprint({ url: 'https://x.com', headers: { server: 'nginx/1.25.0' }, body: '' });
    const fp = r.findings.find((f) => f.type === 'tech_fingerprint');
    expect(fp.cvssScore).toBe(0);
    expect(fp.severity).toBe('informational');
  });

  it('produces nothing for an unfingerprintable response', () => {
    const r = fingerprint({ url: 'https://x.com', headers: {}, body: '<html>plain</html>' });
    expect(r.technologies).toHaveLength(0);
    expect(r.findings).toHaveLength(0);
  });
});
