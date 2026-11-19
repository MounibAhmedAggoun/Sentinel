import { describe, expect, it } from 'vitest';
import type { CookieInfo, HttpHop } from '../../http/types.js';
import { makeScan } from '../fixtures.js';
import { RULE_IDS } from '../ids.js';
import type { ScanResult } from '../types.js';
import { cookieRules } from './cookies.js';

const GOOD: CookieInfo = {
  name: 'sid',
  secure: true,
  httpOnly: true,
  sameSite: 'lax',
  pathIsRoot: false,
  hasDomain: false,
};

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
  it('reports SameSite=None without Secure', () => {
    const findings = cookieRules(
      scanWithCookies([{ ...GOOD, secure: false, sameSite: 'none' }], 'http://example.com/'),
    );

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.COOKIE_SAMESITE_NONE_WITHOUT_SECURE]);
    expect(findings[0]?.evidence).toMatchObject({
      sameSite: 'none',
      secure: false,
      cookies: ['sid'],
    });
    expect(findings[0]?.remediation).not.toBe('');
  });

  it('reports both rules for SameSite=None without Secure over HTTPS', () => {
    const ruleIds = cookieRules(
      scanWithCookies([{ ...GOOD, secure: false, sameSite: 'none' }]),
    ).map((f) => f.ruleId);

    expect(ruleIds).toContain(RULE_IDS.COOKIE_SECURE_MISSING);
    expect(ruleIds).toContain(RULE_IDS.COOKIE_SAMESITE_NONE_WITHOUT_SECURE);
  });

  it('accepts SameSite=None with Secure', () => {
    expect(cookieRules(scanWithCookies([{ ...GOOD, sameSite: 'none' }]))).toEqual([]);
  });

  it('does not flag SameSite=Lax without Secure as SameSite=None', () => {
    const ruleIds = cookieRules(
      scanWithCookies([{ ...GOOD, secure: false, sameSite: 'lax' }], 'http://example.com/'),
    ).map((f) => f.ruleId);

    expect(ruleIds).not.toContain(RULE_IDS.COOKIE_SAMESITE_NONE_WITHOUT_SECURE);
  });

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
        { ...GOOD, name: 'a', httpOnly: false },
        { ...GOOD, name: 'b', httpOnly: false },
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

describe('cookieRules: name prefixes', () => {
  const PREFIX_IDS: string[] = [
    RULE_IDS.COOKIE_SECURE_PREFIX_WITHOUT_SECURE,
    RULE_IDS.COOKIE_HOST_PREFIX_INVALID,
  ];
  const prefixIds = (cookies: CookieInfo[], url?: string): string[] =>
    cookieRules(scanWithCookies(cookies, url))
      .map((f) => f.ruleId)
      .filter((id) => PREFIX_IDS.includes(id));

  const HOST_GOOD: CookieInfo = { ...GOOD, name: '__Host-sid', pathIsRoot: true };

  it('notes a __Secure- cookie without Secure', () => {
    const cookies = [{ ...GOOD, name: '__Secure-sid', secure: false }];

    expect(prefixIds(cookies)).toEqual([RULE_IDS.COOKIE_SECURE_PREFIX_WITHOUT_SECURE]);
  });

  it('accepts a __Secure- cookie with Secure', () => {
    expect(prefixIds([{ ...GOOD, name: '__Secure-sid' }])).toEqual([]);
  });

  it('accepts a __Host- cookie that meets every rule', () => {
    expect(prefixIds([HOST_GOOD])).toEqual([]);
  });

  it('notes a __Host- cookie without Secure', () => {
    expect(prefixIds([{ ...HOST_GOOD, secure: false }])).toEqual([
      RULE_IDS.COOKIE_HOST_PREFIX_INVALID,
    ]);
  });

  it('notes a __Host- cookie without Path=/', () => {
    expect(prefixIds([{ ...HOST_GOOD, pathIsRoot: false }])).toEqual([
      RULE_IDS.COOKIE_HOST_PREFIX_INVALID,
    ]);
  });

  it('notes a __Host- cookie with a Domain attribute', () => {
    expect(prefixIds([{ ...HOST_GOOD, hasDomain: true }])).toEqual([
      RULE_IDS.COOKIE_HOST_PREFIX_INVALID,
    ]);
  });

  it('shows which requirement a __Host- cookie missed, without storing values', () => {
    const findings = cookieRules(scanWithCookies([{ ...HOST_GOOD, hasDomain: true }])).filter(
      (f) => f.ruleId === RULE_IDS.COOKIE_HOST_PREFIX_INVALID,
    );

    expect(findings[0]?.severity).toBe('low');
    expect(findings[0]?.evidence).toEqual({
      prefix: '__Host-',
      cookies: [{ name: '__Host-sid', secure: true, pathIsRoot: true, hasDomain: true }],
    });
  });

  it('does not judge a cookie whose name only contains the prefix', () => {
    const cookies = [
      { ...GOOD, name: 'my__Secure-sid', secure: false },
      { ...GOOD, name: 'x__Host-sid', hasDomain: true },
    ];

    expect(prefixIds(cookies)).toEqual([]);
  });

  it('matches the prefix case-sensitively, as browsers do', () => {
    expect(prefixIds([{ ...GOOD, name: '__secure-sid', secure: false }])).toEqual([]);
  });

  it('does not judge prefixes on a cookie set over plain HTTP', () => {
    const cookies = [{ ...HOST_GOOD, secure: false }];

    expect(prefixIds(cookies, 'http://example.com/')).toEqual([]);
  });
});
