// Canonical vulnerability-type registry — the single source of truth for every
// finding type the engine can emit. Backend, worker, fix-guide coverage tests,
// and the frontend all import from here so the type set never drifts.
//
// Each entry:
//   key      — stable machine id (stored on the vulnerability document)
//   name     — human label for UI/reports
//   owasp    — OWASP Top 10 (2021) category id
//   owaspRef — canonical OWASP reference URL
//   subtypes — known subtype ids (optional; '' = no subtype)

export const OWASP = Object.freeze({
  A01: 'A01:2021 Broken Access Control',
  A02: 'A02:2021 Cryptographic Failures',
  A03: 'A03:2021 Injection',
  A04: 'A04:2021 Insecure Design',
  A05: 'A05:2021 Security Misconfiguration',
  A06: 'A06:2021 Vulnerable and Outdated Components',
  A07: 'A07:2021 Identification and Authentication Failures',
  A08: 'A08:2021 Software and Data Integrity Failures',
  A09: 'A09:2021 Security Logging and Monitoring Failures',
  A10: 'A10:2021 Server-Side Request Forgery',
});

export const VULN_TYPES = Object.freeze({
  // ── A03 Injection ──
  sqli: {
    key: 'sqli', name: 'SQL Injection', owasp: OWASP.A03,
    owaspRef: 'https://owasp.org/www-community/attacks/SQL_Injection',
    subtypes: ['error_based', 'boolean_based', 'time_based'],
  },
  xss: {
    key: 'xss', name: 'Cross-Site Scripting (XSS)', owasp: OWASP.A03,
    owaspRef: 'https://owasp.org/www-community/attacks/xss/',
    subtypes: ['reflected', 'stored'],
  },
  cmd_injection: {
    key: 'cmd_injection', name: 'Command Injection', owasp: OWASP.A03,
    owaspRef: 'https://owasp.org/www-community/attacks/Command_Injection',
    subtypes: [],
  },
  ldap_injection: {
    key: 'ldap_injection', name: 'LDAP Injection', owasp: OWASP.A03,
    owaspRef: 'https://owasp.org/www-community/attacks/LDAP_Injection',
    subtypes: [],
  },
  xpath_injection: {
    key: 'xpath_injection', name: 'XPath Injection', owasp: OWASP.A03,
    owaspRef: 'https://owasp.org/www-community/attacks/XPATH_Injection',
    subtypes: [],
  },
  nosql_injection: {
    key: 'nosql_injection', name: 'NoSQL Injection', owasp: OWASP.A03,
    owaspRef: 'https://owasp.org/www-community/attacks/NoSQL_Injection',
    subtypes: [],
  },
  ssti: {
    key: 'ssti', name: 'Server-Side Template Injection (SSTI)', owasp: OWASP.A03,
    owaspRef: 'https://owasp.org/www-community/attacks/Server-Side_Template_Injection',
    subtypes: [],
  },
  crlf_injection: {
    key: 'crlf_injection', name: 'CRLF Injection / HTTP Response Splitting', owasp: OWASP.A03,
    owaspRef: 'https://owasp.org/www-community/vulnerabilities/CRLF_Injection',
    subtypes: [],
  },

  // ── A01 Broken Access Control ──
  idor: {
    key: 'idor', name: 'Insecure Direct Object Reference (IDOR)', owasp: OWASP.A01,
    owaspRef: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
    subtypes: [],
  },
  forced_browsing: {
    key: 'forced_browsing', name: 'Forced Browsing', owasp: OWASP.A01,
    owaspRef: 'https://owasp.org/www-community/attacks/Forced_browsing',
    subtypes: [],
  },
  path_traversal: {
    key: 'path_traversal', name: 'Path Traversal', owasp: OWASP.A01,
    owaspRef: 'https://owasp.org/www-community/attacks/Path_Traversal',
    subtypes: ['lfi', 'directory_traversal'],
  },

  // ── A02 Cryptographic Failures ──
  no_https: {
    key: 'no_https', name: 'Cleartext Transport (No HTTPS)', owasp: OWASP.A02,
    owaspRef: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    subtypes: [],
  },
  weak_tls: {
    key: 'weak_tls', name: 'Weak TLS Configuration', owasp: OWASP.A02,
    owaspRef: 'https://owasp.org/www-project-transport-layer-security/',
    subtypes: [],
  },
  sensitive_data_in_url: {
    key: 'sensitive_data_in_url', name: 'Sensitive Data in URL', owasp: OWASP.A02,
    owaspRef: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    subtypes: [],
  },
  missing_hsts: {
    key: 'missing_hsts', name: 'Missing HSTS Header', owasp: OWASP.A02,
    owaspRef: 'https://owasp.org/www-project-secure-headers/#http-strict-transport-security',
    subtypes: [],
  },
  exposed_secret: {
    key: 'exposed_secret', name: 'Exposed Secret / Credential', owasp: OWASP.A02,
    owaspRef: 'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials',
    subtypes: ['critical', 'high', 'medium', 'low'],
  },

  // ── A04 Insecure Design ──
  mass_assignment: {
    key: 'mass_assignment', name: 'Mass Assignment', owasp: OWASP.A04,
    owaspRef: 'https://owasp.org/www-community/vulnerabilities/Mass_Assignment_Cheat_Sheet',
    subtypes: [],
  },
  predictable_resource: {
    key: 'predictable_resource', name: 'Predictable Resource Location', owasp: OWASP.A04,
    owaspRef: 'https://owasp.org/Top10/A04_2021-Insecure_Design/',
    subtypes: [],
  },

  // ── A05 Security Misconfiguration ──
  default_credentials: {
    key: 'default_credentials', name: 'Default Credentials', owasp: OWASP.A05,
    owaspRef: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    subtypes: [],
  },
  exposed_admin_panel: {
    key: 'exposed_admin_panel', name: 'Exposed Admin Panel', owasp: OWASP.A05,
    owaspRef: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    subtypes: [],
  },
  directory_listing: {
    key: 'directory_listing', name: 'Directory Listing Enabled', owasp: OWASP.A05,
    owaspRef: 'https://owasp.org/www-community/Improper_Data_Validation',
    subtypes: [],
  },
  exposed_sensitive_file: {
    key: 'exposed_sensitive_file', name: 'Exposed Sensitive File (.env/.git)', owasp: OWASP.A05,
    owaspRef: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    subtypes: [],
  },
  xxe: {
    key: 'xxe', name: 'XML External Entity (XXE)', owasp: OWASP.A05,
    owaspRef: 'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing',
    subtypes: [],
  },
  verbose_error: {
    key: 'verbose_error', name: 'Verbose Error Message', owasp: OWASP.A05,
    owaspRef: 'https://owasp.org/www-community/Improper_Error_Handling',
    subtypes: [],
  },
  missing_security_header: {
    key: 'missing_security_header', name: 'Missing Security Header', owasp: OWASP.A05,
    owaspRef: 'https://owasp.org/www-project-secure-headers/',
    subtypes: ['csp', 'x_frame_options', 'x_content_type_options'],
  },
  cors_misconfig: {
    key: 'cors_misconfig', name: 'CORS Misconfiguration', owasp: OWASP.A05,
    owaspRef: 'https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny',
    subtypes: [],
  },
  server_version_disclosure: {
    key: 'server_version_disclosure', name: 'Server Version Disclosure', owasp: OWASP.A05,
    owaspRef: 'https://owasp.org/www-project-secure-headers/',
    subtypes: [],
  },

  // ── A06 Vulnerable & Outdated Components ──
  tech_fingerprint: {
    key: 'tech_fingerprint', name: 'Technology Fingerprint', owasp: OWASP.A06,
    owaspRef: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
    subtypes: [],
  },
  known_cve: {
    key: 'known_cve', name: 'Known CVE in Component', owasp: OWASP.A06,
    owaspRef: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
    subtypes: [],
  },

  // ── A07 Identification & Authentication Failures ──
  auth_bypass: {
    key: 'auth_bypass', name: 'Authentication Bypass', owasp: OWASP.A07,
    owaspRef: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
    subtypes: ['sqli'],
  },
  weak_session_token: {
    key: 'weak_session_token', name: 'Weak Session Token', owasp: OWASP.A07,
    owaspRef: 'https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length',
    subtypes: [],
  },
  session_fixation: {
    key: 'session_fixation', name: 'Session Fixation', owasp: OWASP.A07,
    owaspRef: 'https://owasp.org/www-community/attacks/Session_fixation',
    subtypes: [],
  },
  jwt_alg_none: {
    key: 'jwt_alg_none', name: 'JWT Algorithm Confusion (alg:none)', owasp: OWASP.A07,
    owaspRef: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens',
    subtypes: [],
  },
  missing_logout: {
    key: 'missing_logout', name: 'Missing Session Invalidation on Logout', owasp: OWASP.A07,
    owaspRef: 'https://owasp.org/www-community/Session_Management_Cheat_Sheet',
    subtypes: [],
  },
  no_rate_limit_auth: {
    key: 'no_rate_limit_auth', name: 'No Brute-Force Protection', owasp: OWASP.A07,
    owaspRef: 'https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks',
    subtypes: [],
  },

  // ── A08 Software & Data Integrity Failures ──
  open_redirect: {
    key: 'open_redirect', name: 'Open Redirect', owasp: OWASP.A08,
    owaspRef: 'https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet',
    subtypes: [],
  },
  parameter_tampering: {
    key: 'parameter_tampering', name: 'Parameter Tampering', owasp: OWASP.A08,
    owaspRef: 'https://owasp.org/www-community/attacks/Web_Parameter_Tampering',
    subtypes: [],
  },

  // ── A09 Security Logging & Monitoring Failures ──
  no_rate_limit: {
    key: 'no_rate_limit', name: 'No Rate Limiting', owasp: OWASP.A09,
    owaspRef: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/',
    subtypes: [],
  },

  // ── A10 SSRF ──
  ssrf: {
    key: 'ssrf', name: 'Server-Side Request Forgery (SSRF)', owasp: OWASP.A10,
    owaspRef: 'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
    subtypes: ['basic', 'blind'],
  },

  // ── Cross-cutting ──
  csrf: {
    key: 'csrf', name: 'Cross-Site Request Forgery (CSRF)', owasp: OWASP.A01,
    owaspRef: 'https://owasp.org/www-community/attacks/csrf',
    subtypes: [],
  },
  insecure_cookie: {
    key: 'insecure_cookie', name: 'Insecure Cookie Flags', owasp: OWASP.A05,
    owaspRef: 'https://owasp.org/www-community/controls/SecureCookieAttribute',
    subtypes: ['missing_httponly', 'missing_secure', 'missing_samesite'],
  },
  info_disclosure: {
    key: 'info_disclosure', name: 'Information Disclosure', owasp: OWASP.A05,
    owaspRef: 'https://owasp.org/www-community/Improper_Error_Handling',
    subtypes: ['email', 'internal_ip', 'stack_trace'],
  },
});

// Frozen array of all valid type keys — handy for validation and coverage tests.
export const VULN_TYPE_KEYS = Object.freeze(Object.keys(VULN_TYPES));

/** True if `key` is a registered vulnerability type. */
export function isValidVulnType(key) {
  return Object.prototype.hasOwnProperty.call(VULN_TYPES, key);
}

/** Get the registry entry for a type key, or throw if unknown. */
export function getVulnType(key) {
  const entry = VULN_TYPES[key];
  if (!entry) throw new Error(`Unknown vulnerability type: ${key}`);
  return entry;
}
