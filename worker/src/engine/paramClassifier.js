// Parameter Classifier (PRD §9.5a) — maps parameter names to attack categories.
// Pure function, no I/O, fully unit-testable.

export const PARAM_CATEGORIES = Object.freeze({
  NUMERIC_ID: 'NUMERIC_ID',
  SEARCH_FIELD: 'SEARCH_FIELD',
  FILE_PATH: 'FILE_PATH',
  URL_FIELD: 'URL_FIELD',
  EMAIL: 'EMAIL',
  COMMAND: 'COMMAND',
  AUTH_FIELD: 'AUTH_FIELD',
  TEXT_FIELD: 'TEXT_FIELD',
  NUMERIC_BUSINESS: 'NUMERIC_BUSINESS',
  PRIVILEGE_FIELD: 'PRIVILEGE_FIELD',
  HIDDEN_FIELD: 'HIDDEN_FIELD',
  GENERIC: 'GENERIC',
});

// Attack types per category (ordered by priority).
export const CATEGORY_ATTACKS = Object.freeze({
  NUMERIC_ID: ['sqli', 'idor'],
  SEARCH_FIELD: ['xss', 'sqli', 'nosql_injection'],
  FILE_PATH: ['path_traversal', 'ssrf'],
  URL_FIELD: ['open_redirect', 'ssrf', 'crlf_injection'],
  EMAIL: ['xss'],
  COMMAND: ['cmd_injection', 'ssti'],
  AUTH_FIELD: ['auth_bypass', 'sqli', 'nosql_injection', 'ldap_injection'],
  TEXT_FIELD: ['xss'],
  NUMERIC_BUSINESS: ['parameter_tampering'],
  PRIVILEGE_FIELD: ['mass_assignment'],
  HIDDEN_FIELD: ['csrf', 'parameter_tampering'],
  GENERIC: ['xss', 'sqli'],
});

// Keyword sets per category (checked against lowercased param name).
const RULES = [
  { category: 'NUMERIC_ID', keywords: ['id', 'uid', 'user_id', 'product_id', 'item_id', 'post_id', 'order_id', 'record_id', 'pid', 'nid', 'eid'] },
  { category: 'SEARCH_FIELD', keywords: ['search', 'q', 'query', 'keyword', 'term', 'find', 'filter', 'text', 's', 'kw'] },
  { category: 'FILE_PATH', keywords: ['file', 'path', 'dir', 'folder', 'template', 'page', 'include', 'load', 'read', 'document', 'doc', 'filename', 'filepath', 'content', 'resource'] },
  { category: 'URL_FIELD', keywords: ['redirect', 'url', 'uri', 'next', 'return', 'goto', 'destination', 'dest', 'redir', 'target', 'link', 'ref', 'referer', 'callback', 'continue', 'forward', 'src', 'source', 'fetch', 'feed', 'proxy', 'remote', 'webhook', 'imageurl', 'image_url', 'fileurl', 'file_url', 'site', 'domain', 'host'] },
  { category: 'EMAIL', keywords: ['email', 'mail', 'e-mail'] },
  { category: 'COMMAND', keywords: ['cmd', 'exec', 'command', 'run', 'ping', 'host', 'ip', 'shell', 'execute', 'system'] },
  { category: 'AUTH_FIELD', keywords: ['user', 'username', 'login', 'uname', 'pass', 'password', 'auth', 'token', 'secret', 'key', 'apikey', 'api_key', 'credential'] },
  { category: 'TEXT_FIELD', keywords: ['name', 'comment', 'message', 'bio', 'description', 'content', 'body', 'text', 'note', 'title', 'subject', 'msg', 'input', 'data'] },
  { category: 'NUMERIC_BUSINESS', keywords: ['price', 'amount', 'qty', 'quantity', 'total', 'discount', 'cost', 'fee', 'balance', 'credit'] },
  { category: 'PRIVILEGE_FIELD', keywords: ['role', 'admin', 'type', 'level', 'permission', 'group', 'access', 'privilege', 'scope', 'rank'] },
];

/**
 * Classify a parameter into an attack category.
 * @param {string} name  parameter name
 * @param {string} [inputType]  HTML input type (e.g. 'hidden', 'email')
 * @returns {{ category: string, attackTypes: string[] }}
 */
export function classifyParam(name, inputType = 'text') {
  const lower = (name || '').toLowerCase().replace(/[-\s]/g, '_');

  // Hidden inputs → HIDDEN_FIELD regardless of name.
  if (inputType === 'hidden') {
    return { category: PARAM_CATEGORIES.HIDDEN_FIELD, attackTypes: [...CATEGORY_ATTACKS.HIDDEN_FIELD] };
  }

  // Email input type → EMAIL.
  if (inputType === 'email') {
    return { category: PARAM_CATEGORIES.EMAIL, attackTypes: [...CATEGORY_ATTACKS.EMAIL] };
  }

  // Keyword matching — first match wins (rules ordered by specificity).
  // Match on exact equality OR on a complete underscore-delimited segment to
  // avoid "redirect" matching "dir" or "username" matching "name".
  const segments = lower.split('_');
  for (const rule of RULES) {
    if (rule.keywords.some((kw) => lower === kw || segments.includes(kw) || lower.startsWith(kw + '_') || lower.endsWith('_' + kw))) {
      return { category: rule.category, attackTypes: [...CATEGORY_ATTACKS[rule.category]] };
    }
  }

  return { category: PARAM_CATEGORIES.GENERIC, attackTypes: [...CATEGORY_ATTACKS.GENERIC] };
}

/** Classify all params on an endpoint and return the enriched list. */
export function classifyEndpoint(endpoint) {
  return {
    ...endpoint,
    params: (endpoint.params || []).map((p) => {
      const { category, attackTypes } = classifyParam(p.name, p.inputType);
      return { ...p, category, attackTypes };
    }),
  };
}
