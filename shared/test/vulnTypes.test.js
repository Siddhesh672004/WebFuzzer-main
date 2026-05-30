import { describe, it, expect } from 'vitest';
import {
  VULN_TYPES,
  VULN_TYPE_KEYS,
  isValidVulnType,
  getVulnType,
  OWASP,
} from '../src/vulnTypes.js';
import {
  CVSS_VECTORS,
  CVSS_SUBTYPE_VECTORS,
  vectorFor,
} from '../src/cvssVectors.js';
import { severityFromScore } from '../src/severity.js';

describe('vuln type registry', () => {
  it('exposes a non-empty frozen key list', () => {
    expect(VULN_TYPE_KEYS.length).toBeGreaterThan(20);
    expect(Object.isFrozen(VULN_TYPES)).toBe(true);
  });

  it('every entry has key, name, owasp, owaspRef, subtypes', () => {
    for (const key of VULN_TYPE_KEYS) {
      const t = VULN_TYPES[key];
      expect(t.key).toBe(key); // key field matches map key
      expect(t.name).toBeTypeOf('string');
      expect(t.name.length).toBeGreaterThan(0);
      expect(Object.values(OWASP)).toContain(t.owasp);
      expect(t.owaspRef).toMatch(/^https:\/\/owasp\.org\//);
      expect(Array.isArray(t.subtypes)).toBe(true);
    }
  });

  it('isValidVulnType validates membership', () => {
    expect(isValidVulnType('sqli')).toBe(true);
    expect(isValidVulnType('not_a_type')).toBe(false);
  });

  it('getVulnType throws on unknown key', () => {
    expect(() => getVulnType('nope')).toThrow();
    expect(getVulnType('xss').name).toContain('XSS');
  });
});

describe('CVSS vector coverage', () => {
  it('every vuln type has a registered CVSS vector', () => {
    for (const key of VULN_TYPE_KEYS) {
      expect(CVSS_VECTORS[key], `missing CVSS vector for ${key}`).toBeDefined();
    }
  });

  it('every vector string is well-formed CVSS:3.1', () => {
    const all = { ...CVSS_VECTORS, ...CVSS_SUBTYPE_VECTORS };
    for (const [key, { vector, expectedScore }] of Object.entries(all)) {
      expect(vector, key).toMatch(
        /^CVSS:3\.1\/AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH]$/,
      );
      expect(expectedScore, key).toBeGreaterThanOrEqual(0);
      expect(expectedScore, key).toBeLessThanOrEqual(10);
    }
  });

  it('expectedScore severity is internally consistent', () => {
    // A 0.0 vector must be all-None impact; a >0 score must have some impact.
    for (const [key, { vector, expectedScore }] of Object.entries(CVSS_VECTORS)) {
      const allNoneImpact = /C:N\/I:N\/A:N$/.test(vector);
      if (expectedScore === 0) {
        expect(allNoneImpact, `${key} scores 0 but has impact`).toBe(true);
      } else {
        expect(allNoneImpact, `${key} scores >0 but has no impact`).toBe(false);
      }
    }
  });

  it('vectorFor prefers a subtype override', () => {
    expect(vectorFor('xss', 'reflected').expectedScore).toBe(6.1);
    expect(vectorFor('xss', 'stored').expectedScore).toBe(8.7);
  });

  it('vectorFor falls back to the type-level vector', () => {
    expect(vectorFor('sqli').vector).toBe(CVSS_VECTORS.sqli.vector);
    expect(vectorFor('cmd_injection', 'nonexistent_subtype').vector)
      .toBe(CVSS_VECTORS.cmd_injection.vector);
  });

  it('vectorFor throws for an unregistered type', () => {
    expect(() => vectorFor('made_up_type')).toThrow();
  });

  it('expectedScore maps to a sane severity for headline types', () => {
    expect(severityFromScore(vectorFor('sqli').expectedScore)).toBe('critical');
    expect(severityFromScore(vectorFor('xss', 'reflected').expectedScore)).toBe('medium');
    expect(severityFromScore(vectorFor('tech_fingerprint').expectedScore)).toBe('informational');
  });
});
