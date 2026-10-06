import { describe, expect, it } from 'vitest';
import type { CookieInfo, HttpHop } from '../../http/types.js';
import { makeScan } from '../fixtures.js';
import { RULE_IDS } from '../ids.js';
import type { ScanResult } from '../types.js';
import { cookieRules } from './cookies.js';

const GOOD: CookieInfo = { name: 'sid', secure: true, httpOnly: true, sameSite: 'lax' };

function scanWithCookies(cookies: CookieInfo[], url = 'https://example.com/'): ScanResult {
  const base = makeScan();
  const hop = { ...base.http.hops[0]!, url, cookies };
  return { ...base, http: { ...base.http, hops: [hop] } };
}

function scanWithHops(hops: Pick<HttpHop, 'url' | 'cookies'>[]): ScanResult {
  const base = makeScan();
  const template = base.http.hops[0]!;
  return { ...base, http: { ...base.http, hops: hops.map((h) => ({ ...template, ...h })) } };
}

describe('cookieRules', () => {
  it('produces nothing when there are no cookies', () => {
    expect(cookieRules(makeScan())).toEqual([]);
  });

  it('produces nothing when every flag is set', () => {
    expect(cookieRules(scanWithCookies([GOOD]))).toEqual([]);
  });

  it('reports a missing Secure flag on an HTTPS response', () => {
    const findings = cookieRules(scanWithCookies([{ ...GOOD, secure: false }]));

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: RULE_IDS.COOKIE_SECURE_MISSING,
      severity: 'low',
      evidence: { flag: 'Secure', cookies: ['sid'] },
    });
    expect(findings[0]?.remediation).not.toBe('');
  });

  it('does not judge Secure on a cookie set over plain HTTP', () => {
    const findings = cookieRules(
      scanWithCookies([{ ...GOOD, secure: false }], 'http://example.com/'),
    );

    expect(findings.map((f) => f.ruleId)).not.toContain(RULE_IDS.COOKIE_SECURE_MISSING);
  });

  it('reports a missing HttpOnly flag', () => {
    const findings = cookieRules(scanWithCookies([{ ...GOOD, httpOnly: false }]));

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.COOKIE_HTTPONLY_MISSING]);
  });

  it('reports a missing SameSite flag', () => {
    const findings = cookieRules(scanWithCookies([{ ...GOOD, sameSite: null }]));

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.COOKIE_SAMESITE_MISSING]);
  });

  it('accepts SameSite=None as present', () => {
    expect(cookieRules(scanWithCookies([{ ...GOOD, sameSite: 'none' }]))).toEqual([]);
  });

  it('groups several cookies under one finding', () => {
    const findings = cookieRules(
      scanWithCookies([
        { name: 'a', secure: true, httpOnly: false, sameSite: 'lax' },
        { name: 'b', secure: true, httpOnly: false, sameSite: 'lax' },
        GOOD,
      ]),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toEqual({ flag: 'HttpOnly', cookies: ['a', 'b'] });
  });

  it('finds cookies set on a redirect hop', () => {
    const findings = cookieRules(
      scanWithHops([
        { url: 'https://example.com/', cookies: [{ ...GOOD, httpOnly: false }] },
        { url: 'https://example.com/home', cookies: [] },
      ]),
    );

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.COOKIE_HTTPONLY_MISSING]);
  });

  it('reports the same cookie name only once across hops', () => {
    const bad = { ...GOOD, httpOnly: false };
    const findings = cookieRules(
      scanWithHops([
        { url: 'https://example.com/', cookies: [bad] },
        { url: 'https://example.com/home', cookies: [bad] },
      ]),
    );

    expect(findings[0]?.evidence).toEqual({ flag: 'HttpOnly', cookies: ['sid'] });
  });

  it('never includes a cookie value in a finding', () => {
    const findings = cookieRules(scanWithCookies([{ ...GOOD, httpOnly: false }]));

    expect(JSON.stringify(findings)).not.toMatch(/value/i);
  });

  it('produces nothing when the HTTP check failed', () => {
    const scan = scanWithCookies([{ ...GOOD, secure: false }]);
    const http = { ...scan.http, error: { code: 'TIMEOUT' as const, message: 'slow' } };

    expect(cookieRules({ ...scan, http })).toEqual([]);
  });
});
