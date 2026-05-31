// Human labels for vuln type keys, mirroring @smartfuzz/shared vulnTypes names
// without importing the whole registry into the bundle. Falls back to a
// title-cased version of the key for any type not listed here.

const LABELS = {
  sqli: 'SQL Injection',
  xss: 'Cross-Site Scripting',
  cmd_injection: 'Command Injection',
  ldap_injection: 'LDAP Injection',
  xpath_injection: 'XPath Injection',
  nosql_injection: 'NoSQL Injection',
  ssti: 'Server-Side Template Injection',
  xxe: 'XML External Entity (XXE)',
  jwt_alg_none: 'JWT alg:none',
  crlf_injection: 'CRLF Injection',
  idor: 'Insecure Direct Object Reference',
  forced_browsing: 'Forced Browsing',
  path_traversal: 'Path Traversal',
  no_https: 'No HTTPS',
  weak_tls: 'Weak TLS',
  sensitive_data_in_url: 'Sensitive Data in URL',
  missing_hsts: 'Missing HSTS',
  mass_assignment: 'Mass Assignment',
  predictable_resource: 'Predictable Resource',
  default_credentials: 'Default Credentials',
  exposed_admin_panel: 'Exposed Admin Panel',
  directory_listing: 'Directory Listing',
  exposed_sensitive_file: 'Exposed Sensitive File',
  verbose_error: 'Verbose Error',
  missing_security_header: 'Missing Security Header',
  cors_misconfig: 'CORS Misconfiguration',
  server_version_disclosure: 'Server Version Disclosure',
  tech_fingerprint: 'Technology Fingerprint',
  known_cve: 'Known CVE',
  auth_bypass: 'Authentication Bypass',
  weak_session_token: 'Weak Session Token',
  session_fixation: 'Session Fixation',
  missing_logout: 'Missing Logout Invalidation',
  no_rate_limit_auth: 'No Brute-Force Protection',
  open_redirect: 'Open Redirect',
  parameter_tampering: 'Parameter Tampering',
  no_rate_limit: 'No Rate Limiting',
  ssrf: 'Server-Side Request Forgery',
  csrf: 'Cross-Site Request Forgery',
  insecure_cookie: 'Insecure Cookie',
  info_disclosure: 'Information Disclosure',
  exposed_secret: 'Exposed Secret',
};

export function getVulnLabel(type) {
  if (LABELS[type]) return LABELS[type];
  return String(type || '')
    .split('_')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

export default getVulnLabel;
