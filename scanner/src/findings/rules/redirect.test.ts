import { describe, expect, it } from 'vitest';
import type { HttpResult } from '../../http/types.js';
import { makeScan } from '../fixtures.js';
import { RULE_IDS } from '../ids.js';
import type { ScanResult } from '../types.js';
import { redirectRules } from './redirect.js';

function withPlain(httpPlain: HttpResult): ScanResult {
  return { ...makeScan(), httpPlain };
}

function hop(url: string, status: number): HttpResult['hops'][number] {
  return {
    url,
    status,
    headers: {},
    cookies: [],
    remoteIp: '93.184.216.34',
    timingMs: 10,
  };
}

describe('redirectRules', () => {
  it('produces nothing when HTTP redirects to HTTPS', () => {
    expect(redirectRules(makeScan())).toEqual([]);
  });

  it('reports a site that answers on plain HTTP without redirecting', () => {
    const findings = redirectRules(
      withPlain({
        startUrl: 'http://example.com/',
        finalUrl: 'http://example.com/',
        hops: [hop('http://example.com/', 200)],
        error: null,
      }),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: RULE_IDS.HTTP_NO_HTTPS_REDIRECT,
      severity: 'low',
      evidence: {
        startUrl: 'http://example.com/',
        finalUrl: 'http://example.com/',
        finalStatus: 200,
        hops: 1,
      },
    });
    expect(findings[0]?.remediation).not.toBe('');
  });

  it('reports a redirect chain that stays on HTTP', () => {
    const findings = redirectRules(
      withPlain({
        startUrl: 'http://example.com/',
        finalUrl: 'http://example.com/home',
        hops: [hop('http://example.com/', 301), hop('http://example.com/home', 200)],
        error: null,
      }),
    );

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.HTTP_NO_HTTPS_REDIRECT]);
    expect(findings[0]?.evidence).toMatchObject({ hops: 2 });
  });

  it('produces nothing when the plain HTTP check failed', () => {
    const findings = redirectRules(
      withPlain({
        startUrl: 'http://example.com/',
        finalUrl: null,
        hops: [],
        error: { code: 'CONNECTION_FAILED', message: 'refused' },
      }),
    );

    expect(findings).toEqual([]);
  });

  it('produces nothing when there were no hops', () => {
    const findings = redirectRules(
      withPlain({ startUrl: 'http://example.com/', finalUrl: null, hops: [], error: null }),
    );

    expect(findings).toEqual([]);
  });

  it('produces nothing when the check did not start on http', () => {
    const findings = redirectRules(
      withPlain({
        startUrl: 'https://example.com/',
        finalUrl: 'https://example.com/',
        hops: [hop('https://example.com/', 200)],
        error: null,
      }),
    );

    expect(findings).toEqual([]);
  });
});
