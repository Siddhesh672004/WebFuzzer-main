import { describe, it, expect } from 'vitest';
import {
  SEVERITY,
  SEVERITY_ORDER,
  SEVERITY_RANK,
  SEVERITY_BANDS,
  SECURITY_SCORE_PENALTY,
  severityFromScore,
  severityColor,
} from '../src/severity.js';

describe('severityFromScore', () => {
  it('maps 0.0 to informational', () => {
    expect(severityFromScore(0)).toBe(SEVERITY.INFORMATIONAL);
  });

  it('maps the low band (0.1–3.9)', () => {
    expect(severityFromScore(0.1)).toBe(SEVERITY.LOW);
    expect(severityFromScore(3.9)).toBe(SEVERITY.LOW);
  });

  it('maps the medium band (4.0–6.9)', () => {
    expect(severityFromScore(4.0)).toBe(SEVERITY.MEDIUM);
    expect(severityFromScore(6.9)).toBe(SEVERITY.MEDIUM);
  });

  it('maps the high band (7.0–8.9)', () => {
    expect(severityFromScore(7.0)).toBe(SEVERITY.HIGH);
    expect(severityFromScore(8.9)).toBe(SEVERITY.HIGH);
  });

  it('maps the critical band (9.0–10.0)', () => {
    expect(severityFromScore(9.0)).toBe(SEVERITY.CRITICAL);
    expect(severityFromScore(10.0)).toBe(SEVERITY.CRITICAL);
  });

  it('treats boundary 7.0 as high, not medium', () => {
    expect(severityFromScore(7.0)).toBe(SEVERITY.HIGH);
  });

  it('throws on non-numeric input', () => {
    expect(() => severityFromScore('9.0')).toThrow(TypeError);
    expect(() => severityFromScore(NaN)).toThrow(TypeError);
  });
});

describe('severity metadata consistency', () => {
  it('SEVERITY_ORDER lists all five bands high → low', () => {
    expect(SEVERITY_ORDER).toEqual([
      SEVERITY.CRITICAL,
      SEVERITY.HIGH,
      SEVERITY.MEDIUM,
      SEVERITY.LOW,
      SEVERITY.INFORMATIONAL,
    ]);
  });

  it('every band has a rank, penalty, and color', () => {
    for (const sev of SEVERITY_ORDER) {
      expect(SEVERITY_RANK[sev]).toBeTypeOf('number');
      expect(SECURITY_SCORE_PENALTY[sev]).toBeTypeOf('number');
      expect(SEVERITY_BANDS[sev].color).toMatch(/^#[0-9A-Fa-f]{6}$/);
    }
  });

  it('ranks are strictly descending', () => {
    const ranks = SEVERITY_ORDER.map((s) => SEVERITY_RANK[s]);
    for (let i = 1; i < ranks.length; i += 1) {
      expect(ranks[i]).toBeLessThan(ranks[i - 1]);
    }
  });

  it('penalties match the PRD scoring scheme', () => {
    expect(SECURITY_SCORE_PENALTY[SEVERITY.CRITICAL]).toBe(20);
    expect(SECURITY_SCORE_PENALTY[SEVERITY.HIGH]).toBe(10);
    expect(SECURITY_SCORE_PENALTY[SEVERITY.MEDIUM]).toBe(5);
    expect(SECURITY_SCORE_PENALTY[SEVERITY.LOW]).toBe(2);
    expect(SECURITY_SCORE_PENALTY[SEVERITY.INFORMATIONAL]).toBe(0);
  });
});

describe('severityColor', () => {
  it('returns the band color', () => {
    expect(severityColor(SEVERITY.CRITICAL)).toBe('#F85149');
  });

  it('falls back to informational gray for unknown input', () => {
    expect(severityColor('nonsense')).toBe('#8B949E');
  });
});
