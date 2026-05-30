// CVSS v3.1 base vectors per vulnerability type.
//
// The PRD ships a table of pre-computed scores. Per IMPLEMENTATION_PLAN §3.2 we
// store the *vector strings* (not just numbers) so the CVSS calculator in the
// worker can recompute the score with the Appendix-A roundup and assert it
// matches. Storing the vector also lets reports show the metric breakdown.
//
// Vector metric keys: AV (Attack Vector), AC (Attack Complexity),
// PR (Privileges Required), UI (User Interaction), S (Scope),
// C/I/A (Confidentiality/Integrity/Availability impact).
//
// NOTE: where a vector has S:C (scope changed), the computed base score is
// higher than the PRD's hand-set number. The calculator is authoritative; the
// `expectedScore` here is the FIRST.org-correct value and is asserted in tests.

export const CVSS_VECTORS = Object.freeze({
  // Full DB compromise, network, no auth, scope changed → 10.0
  sqli: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', expectedScore: 10.0 },
  // OS command execution → 9.8 (scope unchanged: app == OS context)
  cmd_injection: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', expectedScore: 9.8 },
  // SSTI commonly escalates to RCE → 9.8
  ssti: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', expectedScore: 9.8 },
  // Auth bypass: full confidentiality+integrity, scope changed → 9.3
  auth_bypass: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N', expectedScore: 9.3 },
  // Default creds → admin access, high CIA → 9.8
  default_credentials: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', expectedScore: 9.8 },
  // Credential/source exposure: high confidentiality only → 7.5
  exposed_sensitive_file: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', expectedScore: 7.5 },
  // /etc/passwd read = high confidentiality → 7.5
  path_traversal: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', expectedScore: 7.5 },
  // SSRF to internal network: high conf, low integrity, scope changed → 9.3
  ssrf: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N', expectedScore: 9.3 },
  // Stored XSS: scope changed, low CIA, no UI for stored → 8.7
  // (subtype 'reflected' overridden below via CVSS_SUBTYPE_VECTORS)
  xss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N', expectedScore: 8.7 },
  // IDOR: unauthorized data access, high confidentiality → 7.5
  idor: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', expectedScore: 7.5 },
  // Mass assignment: privilege escalation, high integrity → 8.1
  mass_assignment: { vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N', expectedScore: 8.1 },
  // Brute force possible: low conf, integrity via takeover → 7.3
  no_rate_limit_auth: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L', expectedScore: 7.3 },
  // XPath injection: app logic bypass, high confidentiality → 7.5
  xpath_injection: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', expectedScore: 7.5 },
  // LDAP injection → 7.5
  ldap_injection: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', expectedScore: 7.5 },
  // Session fixation → account takeover → 8.0 (AC:H, takeover needs conditions)
  session_fixation: { vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N', expectedScore: 8.0 },
  // Weak/predictable session token → 7.5
  weak_session_token: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', expectedScore: 7.5 },
  // CORS misconfiguration: cross-origin data theft, scope changed → 8.1
  cors_misconfig: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N', expectedScore: 8.1 },
  // NoSQL injection: auth bypass / data dump → 8.1 (scope changed, low impacts)
  nosql_injection: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N', expectedScore: 8.7 },
  // Parameter tampering: business-logic integrity → 7.5
  parameter_tampering: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N', expectedScore: 7.5 },
  // Exposed admin panel → 8.6 (per PRD; high confidentiality + low integrity)
  exposed_admin_panel: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N', expectedScore: 8.2 },
  // Forced browsing: access unlisted pages → 6.5 (low CI)
  forced_browsing: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N', expectedScore: 6.5 },
  // Reflected-ish open redirect: phishing facilitation → 6.1
  open_redirect: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', expectedScore: 6.1 },
  // Sensitive data in URL → 6.5 (low conf via logs/referrer; scope changed)
  sensitive_data_in_url: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', expectedScore: 7.5 },
  // Weak TLS: downgrade potential → 5.9 (AC:H)
  weak_tls: { vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N', expectedScore: 5.9 },
  // Directory listing → 5.3 (low confidentiality)
  directory_listing: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', expectedScore: 5.3 },
  // CSRF: state-changing action → 6.5 (UI:R, integrity)
  csrf: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N', expectedScore: 6.5 },
  // No rate limiting (general) → 5.3
  no_rate_limit: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L', expectedScore: 5.3 },
  // Verbose error / stack trace → 5.3
  verbose_error: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', expectedScore: 5.3 },
  // Predictable resource location → 5.3
  predictable_resource: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', expectedScore: 5.3 },
  // No HTTPS → 5.3 (cleartext, low conf+int via MitM, AC:H)
  no_https: { vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N', expectedScore: 4.8 },
  // Missing logout invalidation → 5.4
  missing_logout: { vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N', expectedScore: 4.8 },
  // Info disclosure (email/IP/stack) → low
  info_disclosure: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', expectedScore: 5.3 },
  // Insecure cookie flags → medium
  insecure_cookie: { vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N', expectedScore: 4.2 },
  // Missing security header → low
  missing_security_header: { vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N', expectedScore: 3.5 },
  // Missing HSTS → low
  missing_hsts: { vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N', expectedScore: 3.5 },
  // Server version disclosure → low
  server_version_disclosure: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', expectedScore: 5.3 },
  // Technology fingerprint → informational (0.0)
  tech_fingerprint: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', expectedScore: 0.0 },
  // Known CVE → score inherited from CVE data at runtime (placeholder vector)
  known_cve: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L', expectedScore: 6.3 },
});

// Subtype-specific overrides. Falls back to the type-level vector if absent.
export const CVSS_SUBTYPE_VECTORS = Object.freeze({
  'xss:reflected': { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', expectedScore: 6.1 },
  'xss:stored': { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N', expectedScore: 8.7 },
  'sqli:error_based': { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', expectedScore: 10.0 },
  'sqli:boolean_based': { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', expectedScore: 10.0 },
  'sqli:time_based': { vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H', expectedScore: 9.9 },
  'path_traversal:directory_traversal': { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', expectedScore: 7.5 },
  'ssrf:blind': { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N', expectedScore: 8.7 },
});

/**
 * Resolve the CVSS vector for a (type, subtype) pair.
 * Prefers a subtype override, then the type-level vector.
 * @returns {{vector:string, expectedScore:number}}
 */
export function vectorFor(type, subtype = '') {
  if (subtype) {
    const k = `${type}:${subtype}`;
    if (CVSS_SUBTYPE_VECTORS[k]) return CVSS_SUBTYPE_VECTORS[k];
  }
  const v = CVSS_VECTORS[type];
  if (!v) throw new Error(`No CVSS vector registered for type: ${type}`);
  return v;
}
