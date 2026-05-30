import { describe, it, expect } from 'vitest';
import {
  signature,
  signatureInput,
  normalizeEndpointPath,
} from '../src/signatures.js';

describe('normalizeEndpointPath', () => {
  it('strips scheme and host from a full URL', () => {
    expect(normalizeEndpointPath('https://example.com/search')).toBe('/search');
  });

  it('drops the query string', () => {
    expect(normalizeEndpointPath('/search?q=hello&page=2')).toBe('/search');
  });

  it('drops the fragment', () => {
    expect(normalizeEndpointPath('/page#section')).toBe('/page');
  });

  it('collapses numeric id segments to :id', () => {
    expect(normalizeEndpointPath('/user/1')).toBe('/user/:id');
    expect(normalizeEndpointPath('/user/99999')).toBe('/user/:id');
  });

  it('collapses /user/1 and /user/2 to the same path', () => {
    expect(normalizeEndpointPath('/user/1')).toBe(normalizeEndpointPath('/user/2'));
  });

  it('collapses UUID segments to :id', () => {
    expect(normalizeEndpointPath('/order/550e8400-e29b-41d4-a716-446655440000'))
      .toBe('/order/:id');
  });

  it('collapses Mongo ObjectId / long hex segments to :id', () => {
    expect(normalizeEndpointPath('/doc/507f1f77bcf86cd799439011')).toBe('/doc/:id');
  });

  it('collapses duplicate slashes', () => {
    expect(normalizeEndpointPath('/a//b///c')).toBe('/a/b/c');
  });

  it('strips trailing slash except root', () => {
    expect(normalizeEndpointPath('/about/')).toBe('/about');
    expect(normalizeEndpointPath('/')).toBe('/');
  });

  it('lowercases path segments', () => {
    expect(normalizeEndpointPath('/Admin/Login')).toBe('/admin/login');
  });

  it('handles empty / nullish input as root', () => {
    expect(normalizeEndpointPath('')).toBe('/');
    expect(normalizeEndpointPath(null)).toBe('/');
    expect(normalizeEndpointPath(undefined)).toBe('/');
  });

  it('adds a leading slash to a bare path', () => {
    expect(normalizeEndpointPath('search')).toBe('/search');
  });
});

describe('signature', () => {
  it('produces a 40-char sha1 hex', () => {
    const sig = signature('sqli', '/login', 'username');
    expect(sig).toMatch(/^[0-9a-f]{40}$/);
  });

  it('is stable for the same inputs', () => {
    expect(signature('xss', '/search', 'q')).toBe(signature('xss', '/search', 'q'));
  });

  it('collapses IDOR on /user/1 and /user/2 to the same signature', () => {
    expect(signature('idor', '/user/1', 'id')).toBe(signature('idor', '/user/2', 'id'));
  });

  it('differs by type', () => {
    expect(signature('sqli', '/login', 'user')).not.toBe(signature('xss', '/login', 'user'));
  });

  it('differs by parameter', () => {
    expect(signature('sqli', '/login', 'user')).not.toBe(signature('sqli', '/login', 'pass'));
  });

  it('ignores query strings (same sig with and without query)', () => {
    expect(signature('xss', '/search?q=1', 'q')).toBe(signature('xss', '/search', 'q'));
  });

  it('is case-insensitive on parameter', () => {
    expect(signature('sqli', '/login', 'User')).toBe(signature('sqli', '/login', 'user'));
  });

  it('handles a global finding (empty parameter)', () => {
    const sig = signature('missing_hsts', 'https://example.com/', '');
    expect(sig).toMatch(/^[0-9a-f]{40}$/);
  });
});

describe('signatureInput', () => {
  it('exposes the normalized input string', () => {
    expect(signatureInput('sqli', 'https://x.com/User/1?a=b', 'ID'))
      .toBe('sqli:/user/:id:id');
  });
});
