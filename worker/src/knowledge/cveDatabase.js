// Local CVE database (PRD §9.7) — a small curated map of {tech, versionRange}
// → known CVE. We ship this as data (no NVD API call at scan time, per the
// zero-external-dependency constraint). Versions use simple semver-ish compare.
// This is intentionally illustrative, not exhaustive; it demonstrates the
// "detect version → match known CVE" pipeline for the viva/report.

export const CVE_DATABASE = {
  // tech key (lowercased) → array of { maxVersion, cve, cvss, severity, desc }
  // A detected version <= maxVersion is considered vulnerable.
  jquery: [
    { maxVersion: '3.4.1', cve: 'CVE-2020-11022', cvss: 6.1, desc: 'jQuery XSS via untrusted HTML in DOM manipulation methods' },
    { maxVersion: '1.8.9', cve: 'CVE-2012-6708', cvss: 6.1, desc: 'jQuery selector XSS' },
  ],
  bootstrap: [
    { maxVersion: '3.4.0', cve: 'CVE-2019-8331', cvss: 6.1, desc: 'Bootstrap XSS in tooltip/popover data-template' },
  ],
  lodash: [
    { maxVersion: '4.17.11', cve: 'CVE-2019-10744', cvss: 9.1, desc: 'lodash prototype pollution via defaultsDeep' },
  ],
  angular: [
    { maxVersion: '1.7.9', cve: 'CVE-2020-7676', cvss: 6.1, desc: 'AngularJS XSS via SVG/xlink:href' },
  ],
  wordpress: [
    { maxVersion: '5.8.2', cve: 'CVE-2022-21661', cvss: 8.0, desc: 'WordPress WP_Query SQL injection' },
  ],
  drupal: [
    { maxVersion: '7.58', cve: 'CVE-2018-7600', cvss: 9.8, desc: 'Drupalgeddon2 remote code execution' },
  ],
  php: [
    { maxVersion: '5.6.40', cve: 'CVE-2019-11043', cvss: 9.8, desc: 'PHP-FPM underflow RCE (env_path_info)' },
  ],
  apache: [
    { maxVersion: '2.4.49', cve: 'CVE-2021-41773', cvss: 7.5, desc: 'Apache path traversal / RCE (mod_cgi)' },
  ],
  nginx: [
    { maxVersion: '1.20.0', cve: 'CVE-2021-23017', cvss: 7.7, desc: 'nginx DNS resolver off-by-one heap write' },
  ],
  openssl: [
    { maxVersion: '1.0.1f', cve: 'CVE-2014-0160', cvss: 7.5, desc: 'Heartbleed — OpenSSL TLS heartbeat memory disclosure' },
  ],
};

/** Compare dotted numeric versions. Returns -1, 0, 1. Non-numeric parts ignored. */
export function compareVersions(a, b) {
  const pa = String(a).split('.').map((n) => parseInt(n, 10) || 0);
  const pb = String(b).split('.').map((n) => parseInt(n, 10) || 0);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i += 1) {
    const x = pa[i] || 0;
    const y = pb[i] || 0;
    if (x < y) return -1;
    if (x > y) return 1;
  }
  return 0;
}

/** Find CVEs affecting tech@version (version <= entry.maxVersion). */
export function matchCves(tech, version) {
  const entries = CVE_DATABASE[String(tech).toLowerCase()];
  if (!entries || !version) return [];
  return entries.filter((e) => compareVersions(version, e.maxVersion) <= 0);
}
