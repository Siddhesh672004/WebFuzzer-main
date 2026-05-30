// Sensitive paths checked by the Exposed Files Scanner (PRD §9.4). Our own data
// file (we ship no Nikto code/db). Each entry maps a path to the vuln type it
// represents when accessible, plus a severity hint via type. Grouped by risk.

export const SENSITIVE_PATHS = [
  // ── Critical: credential / source exposure ──
  { path: '/.env', type: 'exposed_sensitive_file', desc: 'Environment file (credentials)' },
  { path: '/.git/HEAD', type: 'exposed_sensitive_file', desc: 'Git repository metadata', match: /^ref:|^[0-9a-f]{40}/ },
  { path: '/.git/config', type: 'exposed_sensitive_file', desc: 'Git config' },
  { path: '/backup.sql', type: 'exposed_sensitive_file', desc: 'Database dump' },
  { path: '/backup.zip', type: 'exposed_sensitive_file', desc: 'Backup archive' },
  { path: '/db.sqlite', type: 'exposed_sensitive_file', desc: 'SQLite database' },
  { path: '/.aws/credentials', type: 'exposed_sensitive_file', desc: 'AWS credentials' },
  { path: '/id_rsa', type: 'exposed_sensitive_file', desc: 'SSH private key' },
  { path: '/config.php', type: 'exposed_sensitive_file', desc: 'PHP config (may hold secrets)' },
  { path: '/web.config', type: 'exposed_sensitive_file', desc: 'IIS config' },
  { path: '/wp-config.php', type: 'exposed_sensitive_file', desc: 'WordPress config' },
  { path: '/.htpasswd', type: 'exposed_sensitive_file', desc: 'HTTP auth credentials' },
  { path: '/.npmrc', type: 'exposed_sensitive_file', desc: 'npm config (may hold tokens)' },
  { path: '/.dockercfg', type: 'exposed_sensitive_file', desc: 'Docker registry credentials' },

  // ── High: admin / management panels ──
  { path: '/admin', type: 'exposed_admin_panel', desc: 'Admin panel' },
  { path: '/administrator', type: 'exposed_admin_panel', desc: 'Admin panel' },
  { path: '/wp-admin/', type: 'exposed_admin_panel', desc: 'WordPress admin' },
  { path: '/phpmyadmin/', type: 'exposed_admin_panel', desc: 'phpMyAdmin' },
  { path: '/manager/html', type: 'exposed_admin_panel', desc: 'Tomcat manager' },
  { path: '/actuator', type: 'exposed_admin_panel', desc: 'Spring Boot actuator' },
  { path: '/actuator/env', type: 'exposed_sensitive_file', desc: 'Spring actuator env (secrets)' },
  { path: '/console', type: 'exposed_admin_panel', desc: 'H2/Rails console' },
  { path: '/.well-known/security.txt', type: 'predictable_resource', desc: 'security.txt' },

  // ── Medium: API docs / debug ──
  { path: '/api/swagger', type: 'predictable_resource', desc: 'Swagger API docs' },
  { path: '/swagger-ui.html', type: 'predictable_resource', desc: 'Swagger UI' },
  { path: '/api/docs', type: 'predictable_resource', desc: 'API documentation' },
  { path: '/debug', type: 'verbose_error', desc: 'Debug endpoint' },
  { path: '/.DS_Store', type: 'predictable_resource', desc: 'macOS directory metadata' },
  { path: '/server-status', type: 'info_disclosure', desc: 'Apache server-status' },
  { path: '/phpinfo.php', type: 'info_disclosure', desc: 'phpinfo()' },

  // ── Informational: path disclosure ──
  { path: '/robots.txt', type: 'predictable_resource', desc: 'robots.txt' },
  { path: '/sitemap.xml', type: 'predictable_resource', desc: 'sitemap.xml' },
];
