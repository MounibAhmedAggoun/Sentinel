import { describe, expect, it } from 'vitest';
import { parseCookies } from './cookies.js';

describe('parseCookies', () => {
  it('parses all flags', () => {
    expect(parseCookies(['sid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict'])).toEqual([
      { name: 'sid', secure: true, httpOnly: true, sameSite: 'strict' },
    ]);
  });

  it('reports missing flags as false/null', () => {
    expect(parseCookies(['theme=dark; Path=/'])).toEqual([
      { name: 'theme', secure: false, httpOnly: false, sameSite: null },
    ]);
  });

  it('is case-insensitive about attributes', () => {
    expect(parseCookies(['a=b; SECURE; httponly; samesite=LAX'])).toEqual([
      { name: 'a', secure: true, httpOnly: true, sameSite: 'lax' },
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
});
