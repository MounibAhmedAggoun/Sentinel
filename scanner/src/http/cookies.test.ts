import { describe, expect, it } from 'vitest';
import { parseCookies } from './cookies.js';

describe('parseCookies', () => {
  it('parses all flags', () => {
    expect(parseCookies(['sid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict'])).toEqual([
      {
        name: 'sid',
        secure: true,
        httpOnly: true,
        sameSite: 'strict',
        pathIsRoot: true,
        hasDomain: false,
      },
    ]);
  });

  it('reports missing flags as false/null', () => {
    expect(parseCookies(['theme=dark; Path=/'])).toEqual([
      {
        name: 'theme',
        secure: false,
        httpOnly: false,
        sameSite: null,
        pathIsRoot: true,
        hasDomain: false,
      },
    ]);
  });

  it('is case-insensitive about attributes', () => {
    expect(parseCookies(['a=b; SECURE; httponly; samesite=LAX'])).toEqual([
      {
        name: 'a',
        secure: true,
        httpOnly: true,
        sameSite: 'lax',
        pathIsRoot: false,
        hasDomain: false,
      },
    ]);
  });

  it('ignores an invalid SameSite value', () => {
    expect(parseCookies(['a=b; SameSite=weird'])[0]?.sameSite).toBeNull();
  });

  it('parses multiple cookies', () => {
    const result = parseCookies(['a=1; Secure', 'b=2; HttpOnly']);
    expect(result.map((c) => c.name)).toEqual(['a', 'b']);
  });

  it('never includes the cookie value', () => {
    expect(JSON.stringify(parseCookies(['sid=SUPERSECRET; Secure']))).not.toContain('SUPERSECRET');
  });

  it('skips malformed cookies with no name', () => {
    expect(parseCookies(['', '=value; Secure'])).toEqual([]);
  });

  it('records whether Path is exactly the root', () => {
    expect(parseCookies(['a=b; Path=/'])[0]?.pathIsRoot).toBe(true);
    expect(parseCookies(['a=b; path=/'])[0]?.pathIsRoot).toBe(true);
    expect(parseCookies(['a=b; Path=/app'])[0]?.pathIsRoot).toBe(false);
    expect(parseCookies(['a=b'])[0]?.pathIsRoot).toBe(false);
  });

  it('records whether a Domain attribute is present', () => {
    expect(parseCookies(['a=b; Domain=example.com'])[0]?.hasDomain).toBe(true);
    expect(parseCookies(['a=b; DOMAIN=example.com'])[0]?.hasDomain).toBe(true);
    expect(parseCookies(['a=b; Path=/'])[0]?.hasDomain).toBe(false);
  });

  it('never includes the Path or Domain text', () => {
    const json = JSON.stringify(parseCookies(['a=b; Path=/secret-path; Domain=private.example']));

    expect(json).not.toContain('secret-path');
    expect(json).not.toContain('private.example');
  });
});
