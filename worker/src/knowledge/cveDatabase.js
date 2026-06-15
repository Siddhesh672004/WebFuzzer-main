// Local CVE database (PRD §9.7) — a small curated map of {tech, versionRange}
// → known CVE. We ship this as data (no NVD API call at scan time, per the
// zero-external-dependency constraint). Versions use simple semver-ish compare.
// This is intentionally illustrative, not exhaustive; it demonstrates the
// "detect version → match known CVE" pipeline for the viva/report.

export const CVE_DATABASE = {
  // tech key (lowercased) → array of { maxVersion, cve, cvss, desc, patchVersion? }
  // A detected version <= maxVersion is considered vulnerable.

  // ── Frontend JS libraries ──
  jquery: [
    { maxVersion: '3.4.1', cve: 'CVE-2020-11022', cvss: 6.1, desc: 'jQuery XSS via untrusted HTML in DOM manipulation methods', patchVersion: '3.5.0' },
    { maxVersion: '3.4.1', cve: 'CVE-2020-11023', cvss: 6.1, desc: 'jQuery XSS via <option> elements passed to manipulation methods', patchVersion: '3.5.0' },
    { maxVersion: '1.8.9', cve: 'CVE-2012-6708', cvss: 6.1, desc: 'jQuery selector XSS', patchVersion: '1.9.0' },
  ],
  bootstrap: [
    { maxVersion: '3.4.0', cve: 'CVE-2019-8331', cvss: 6.1, desc: 'Bootstrap XSS in tooltip/popover data-template', patchVersion: '3.4.1' },
    { maxVersion: '4.3.0', cve: 'CVE-2019-8331', cvss: 6.1, desc: 'Bootstrap 4 XSS in tooltip/popover data-template', patchVersion: '4.3.1' },
  ],
  lodash: [
    { maxVersion: '4.17.11', cve: 'CVE-2019-10744', cvss: 9.1, desc: 'lodash prototype pollution via defaultsDeep', patchVersion: '4.17.12' },
    { maxVersion: '4.17.15', cve: 'CVE-2020-8203', cvss: 7.4, desc: 'lodash prototype pollution via zipObjectDeep', patchVersion: '4.17.19' },
    { maxVersion: '4.17.20', cve: 'CVE-2021-23337', cvss: 7.2, desc: 'lodash command injection via template', patchVersion: '4.17.21' },
  ],
  angular: [
    { maxVersion: '1.7.9', cve: 'CVE-2020-7676', cvss: 6.1, desc: 'AngularJS XSS via SVG/xlink:href', patchVersion: '1.8.0' },
    { maxVersion: '1.8.0', cve: 'CVE-2022-25844', cvss: 5.3, desc: 'AngularJS ReDoS via crafted locale', patchVersion: '1.8.3' },
  ],
  react: [
    { maxVersion: '16.4.1', cve: 'CVE-2018-6341', cvss: 6.1, desc: 'react-dom XSS via crafted attribute names in server rendering', patchVersion: '16.4.2' },
  ],
  vue: [
    { maxVersion: '2.6.10', cve: 'CVE-2019-1010266', cvss: 6.5, desc: 'Vue.js ReDoS in template compiler', patchVersion: '2.6.11' },
  ],
  moment: [
    { maxVersion: '2.29.3', cve: 'CVE-2022-31129', cvss: 7.5, desc: 'moment.js ReDoS in string-to-date parsing', patchVersion: '2.29.4' },
    { maxVersion: '2.19.2', cve: 'CVE-2017-18214', cvss: 7.5, desc: 'moment.js ReDoS in duration parsing', patchVersion: '2.19.3' },
  ],

  // ── CMS ──
  wordpress: [
    { maxVersion: '5.8.2', cve: 'CVE-2022-21661', cvss: 8.0, desc: 'WordPress WP_Query SQL injection', patchVersion: '5.8.3' },
    { maxVersion: '4.7.1', cve: 'CVE-2017-5487', cvss: 5.3, desc: 'WordPress REST API user enumeration', patchVersion: '4.7.2' },
    { maxVersion: '5.0.0', cve: 'CVE-2019-8942', cvss: 8.8, desc: 'WordPress crafted image RCE via path traversal', patchVersion: '5.0.1' },
  ],
  drupal: [
    { maxVersion: '7.58', cve: 'CVE-2018-7600', cvss: 9.8, desc: 'Drupalgeddon2 remote code execution', patchVersion: '7.59' },
    { maxVersion: '7.59', cve: 'CVE-2018-7602', cvss: 9.8, desc: 'Drupal RCE follow-up to Drupalgeddon2', patchVersion: '7.60' },
    { maxVersion: '8.5.0', cve: 'CVE-2019-6340', cvss: 8.1, desc: 'Drupal core RCE via unsanitized REST', patchVersion: '8.6.10' },
  ],
  joomla: [
    { maxVersion: '3.4.5', cve: 'CVE-2015-8562', cvss: 9.8, desc: 'Joomla PHP object injection RCE via User-Agent', patchVersion: '3.4.6' },
    { maxVersion: '4.2.7', cve: 'CVE-2023-23752', cvss: 5.3, desc: 'Joomla improper API access — config/secret disclosure', patchVersion: '4.2.8' },
  ],

  // ── Backend frameworks ──
  laravel: [
    { maxVersion: '8.4.2', cve: 'CVE-2021-3129', cvss: 9.8, desc: 'Laravel Ignition RCE in debug mode', patchVersion: '8.4.3' },
    { maxVersion: '5.6.29', cve: 'CVE-2018-15133', cvss: 8.1, desc: 'Laravel deserialization RCE with leaked APP_KEY', patchVersion: '5.6.30' },
  ],
  django: [
    { maxVersion: '3.2.12', cve: 'CVE-2022-28346', cvss: 9.8, desc: 'Django QuerySet.annotate SQL injection', patchVersion: '3.2.13' },
    { maxVersion: '3.1.13', cve: 'CVE-2021-35042', cvss: 9.8, desc: 'Django QuerySet.order_by SQL injection', patchVersion: '3.1.14' },
  ],
  flask: [
    { maxVersion: '2.2.4', cve: 'CVE-2023-30861', cvss: 7.5, desc: 'Flask cookie disclosure via response caching with Werkzeug', patchVersion: '2.2.5' },
  ],
  rails: [
    { maxVersion: '5.2.2', cve: 'CVE-2019-5418', cvss: 7.5, desc: 'Rails Action View file content disclosure via crafted Accept header', patchVersion: '5.2.2.1' },
    { maxVersion: '7.0.3', cve: 'CVE-2022-32224', cvss: 9.8, desc: 'Rails Active Record RCE via YAML deserialization of serialized columns', patchVersion: '7.0.3.1' },
  ],
  express: [
    { maxVersion: '4.19.1', cve: 'CVE-2024-29041', cvss: 6.1, desc: 'Express open redirect via malformed URLs in res.location', patchVersion: '4.19.2' },
    { maxVersion: '4.17.2', cve: 'CVE-2022-24999', cvss: 7.5, desc: 'Express qs prototype pollution / DoS', patchVersion: '4.17.3' },
  ],
  spring: [
    { maxVersion: '5.3.17', cve: 'CVE-2022-22965', cvss: 9.8, desc: 'Spring4Shell — Spring Framework RCE via data binding', patchVersion: '5.3.18' },
    { maxVersion: '3.1.6', cve: 'CVE-2022-22963', cvss: 9.8, desc: 'Spring Cloud Function SpEL RCE', patchVersion: '3.1.7' },
  ],
  struts: [
    { maxVersion: '2.3.31', cve: 'CVE-2017-5638', cvss: 10.0, desc: 'Apache Struts2 Jakarta multipart RCE', patchVersion: '2.3.32' },
    { maxVersion: '2.5.16', cve: 'CVE-2018-11776', cvss: 8.1, desc: 'Apache Struts2 namespace RCE', patchVersion: '2.5.17' },
  ],

  // ── App / web servers ──
  apache: [
    { maxVersion: '2.4.49', cve: 'CVE-2021-41773', cvss: 7.5, desc: 'Apache path traversal / RCE (mod_cgi)', patchVersion: '2.4.50' },
    { maxVersion: '2.4.50', cve: 'CVE-2021-42013', cvss: 9.8, desc: 'Apache path traversal RCE (incomplete 41773 fix)', patchVersion: '2.4.51' },
  ],
  nginx: [
    { maxVersion: '1.20.0', cve: 'CVE-2021-23017', cvss: 7.7, desc: 'nginx DNS resolver off-by-one heap write', patchVersion: '1.20.1' },
    { maxVersion: '1.21.0', cve: 'CVE-2019-20372', cvss: 5.3, desc: 'nginx error_page request smuggling', patchVersion: '1.17.7' },
  ],
  tomcat: [
    { maxVersion: '9.0.30', cve: 'CVE-2020-1938', cvss: 9.8, desc: 'Ghostcat — Tomcat AJP file read / RCE', patchVersion: '9.0.31' },
    { maxVersion: '9.0.0', cve: 'CVE-2017-12617', cvss: 8.1, desc: 'Tomcat RCE via JSP upload (PUT) with readonly off', patchVersion: '9.0.1' },
  ],
  iis: [
    { maxVersion: '6.0', cve: 'CVE-2017-7269', cvss: 9.8, desc: 'IIS 6.0 WebDAV ScStoragePathFromUrl buffer overflow RCE' },
    { maxVersion: '8.5', cve: 'CVE-2015-1635', cvss: 9.8, desc: 'HTTP.sys remote code execution (MS15-034)' },
  ],
  jenkins: [
    { maxVersion: '2.137', cve: 'CVE-2018-1000861', cvss: 9.8, desc: 'Jenkins Stapler RCE via crafted requests', patchVersion: '2.138' },
  ],
  phpmyadmin: [
    { maxVersion: '4.6.2', cve: 'CVE-2016-5734', cvss: 9.8, desc: 'phpMyAdmin RCE via preg_replace eval modifier', patchVersion: '4.6.3' },
  ],

  // ── Languages / runtimes ──
  php: [
    { maxVersion: '5.6.40', cve: 'CVE-2019-11043', cvss: 9.8, desc: 'PHP-FPM underflow RCE (env_path_info)', patchVersion: '7.1.33' },
    { maxVersion: '8.1.0', cve: 'CVE-2024-4577', cvss: 9.8, desc: 'PHP-CGI argument injection RCE (Windows)', patchVersion: '8.1.29' },
  ],
  nodejs: [
    { maxVersion: '14.20.0', cve: 'CVE-2022-32212', cvss: 8.1, desc: 'Node.js DNS rebinding in --inspect (IsAllowedHost bypass)', patchVersion: '14.20.1' },
  ],

  // ── Crypto / data stores ──
  openssl: [
    { maxVersion: '1.0.1f', cve: 'CVE-2014-0160', cvss: 7.5, desc: 'Heartbleed — OpenSSL TLS heartbeat memory disclosure', patchVersion: '1.0.1g' },
    { maxVersion: '3.0.6', cve: 'CVE-2022-3602', cvss: 7.5, desc: 'OpenSSL X.509 punycode buffer overflow', patchVersion: '3.0.7' },
  ],
  mysql: [
    { maxVersion: '5.7.14', cve: 'CVE-2016-6662', cvss: 9.8, desc: 'MySQL RCE / privilege escalation via malicious config', patchVersion: '5.7.15' },
  ],
  mongodb: [
    { maxVersion: '3.6.7', cve: 'CVE-2019-2386', cvss: 7.1, desc: 'MongoDB user deletion auth bypass on restart', patchVersion: '3.6.13' },
  ],
  redis: [
    { maxVersion: '6.2.6', cve: 'CVE-2022-0543', cvss: 10.0, desc: 'Redis Lua sandbox escape RCE (Debian/Ubuntu packaging)', patchVersion: '6.2.7' },
    { maxVersion: '5.0.0', cve: 'CVE-2021-32626', cvss: 7.5, desc: 'Redis Lua scripting heap overflow RCE', patchVersion: '6.2.6' },
  ],

  // ── Logging ──
  log4j: [
    { maxVersion: '2.14.1', cve: 'CVE-2021-44228', cvss: 10.0, desc: 'Log4Shell — Log4j JNDI lookup RCE', patchVersion: '2.17.1' },
    { maxVersion: '2.16.0', cve: 'CVE-2021-45105', cvss: 5.9, desc: 'Log4j uncontrolled recursion DoS', patchVersion: '2.17.0' },
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
