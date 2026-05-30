import { describe, it, expect } from 'vitest';
import { parseWordlist, normalizeRecords, summarizeByType } from '../wordlistParser.js';
import { CURATED_PAYLOADS } from '../curated.js';
import { isValidVulnType } from '@smartfuzz/shared/vulnTypes';

describe('parseWordlist', () => {
  it('parses one payload per line', () => {
    const raw = "' OR 1=1 --\n<script>alert(1)</script>\n../../etc/passwd";
    const out = parseWordlist(raw, { type: 'sqli', source: 'seclists' });
    expect(out).toHaveLength(3);
    expect(out[0]).toMatchObject({ type: 'sqli', source: 'seclists', value: "' OR 1=1 --" });
  });

  it('skips blank lines and comments', () => {
    const raw = "# a comment\n\n' OR 1=1\n// another\n   \npayload2";
    const out = parseWordlist(raw, { type: 'sqli', source: 'custom' });
    expect(out.map((r) => r.value)).toEqual(["' OR 1=1", 'payload2']);
  });

  it('trims trailing CR from Windows files', () => {
    const raw = "payload1\r\npayload2\r\n";
    const out = parseWordlist(raw, { type: 'xss', source: 'seclists' });
    expect(out.map((r) => r.value)).toEqual(['payload1', 'payload2']);
  });

  it('de-dups within a file', () => {
    const raw = 'dup\ndup\nunique';
    const out = parseWordlist(raw, { type: 'sqli', source: 'custom' });
    expect(out).toHaveLength(2);
  });

  it('carries categories and tags through', () => {
    const out = parseWordlist('x', { type: 'sqli', source: 'fuzzdb', categories: ['NUMERIC_ID'], tags: ['t'] });
    expect(out[0].categories).toEqual(['NUMERIC_ID']);
    expect(out[0].tags).toEqual(['t']);
  });

  it('throws on an invalid type', () => {
    expect(() => parseWordlist('x', { type: 'bogus', source: 'custom' })).toThrow();
  });

  it('returns [] for non-string input', () => {
    expect(parseWordlist(null, { type: 'sqli' })).toEqual([]);
  });
});

describe('normalizeRecords', () => {
  it('drops invalid types and empty values', () => {
    const { records, dropped } = normalizeRecords([
      { type: 'sqli', value: "'" },
      { type: 'bogus', value: 'x' },
      { type: 'xss', value: '' },
      { type: 'xss', value: '   ' },
    ]);
    expect(records).toHaveLength(1);
    expect(dropped).toBe(3);
  });

  it('de-dups across the set by (type, value), last wins', () => {
    const { records } = normalizeRecords([
      { type: 'sqli', value: "'", source: 'seclists', tags: ['a'] },
      { type: 'sqli', value: "'", source: 'custom', tags: ['b'] },
    ]);
    expect(records).toHaveLength(1);
    expect(records[0].tags).toEqual(['b']); // last wins
  });

  it('coerces an unknown source to custom', () => {
    const { records } = normalizeRecords([{ type: 'sqli', value: 'x', source: 'hackerone' }]);
    expect(records[0].source).toBe('custom');
  });

  it('keeps a known source', () => {
    const { records } = normalizeRecords([{ type: 'sqli', value: 'x', source: 'fuzzdb' }]);
    expect(records[0].source).toBe('fuzzdb');
  });

  it('marks records active', () => {
    const { records } = normalizeRecords([{ type: 'sqli', value: 'x' }]);
    expect(records[0].isActive).toBe(true);
  });
});

describe('summarizeByType', () => {
  it('counts records per type', () => {
    const counts = summarizeByType([
      { type: 'sqli', value: 'a' },
      { type: 'sqli', value: 'b' },
      { type: 'xss', value: 'c' },
    ]);
    expect(counts).toEqual({ sqli: 2, xss: 1 });
  });
});

describe('curated payload set', () => {
  it('every curated payload has a valid type and non-empty value', () => {
    for (const p of CURATED_PAYLOADS) {
      expect(isValidVulnType(p.type), `bad type: ${p.type}`).toBe(true);
      expect(typeof p.value).toBe('string');
      expect(p.value.length).toBeGreaterThan(0);
    }
  });

  it('normalizes cleanly with nothing dropped', () => {
    const { records, dropped } = normalizeRecords(CURATED_PAYLOADS);
    expect(dropped).toBe(0);
    expect(records.length).toBeGreaterThan(40);
  });

  it('covers the headline injection types', () => {
    const types = new Set(CURATED_PAYLOADS.map((p) => p.type));
    for (const t of ['sqli', 'xss', 'path_traversal', 'cmd_injection', 'ssti', 'open_redirect', 'ssrf']) {
      expect(types.has(t), `missing curated payloads for ${t}`).toBe(true);
    }
  });
});
