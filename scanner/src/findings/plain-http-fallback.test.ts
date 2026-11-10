import { describe, expect, it } from 'vitest';
import type { CookieInfo, HttpErrorCode } from '../http/types.js';
import { makeScan } from './fixtures.js';
import { finalHop, judgedChain } from './helpers.js';
import { RULE_IDS } from './ids.js';
import { cookieRules } from './rules/cookies.js';
import { disclosureRules } from './rules/disclosure.js';
import { headerRules } from './rules/headers.js';
import type { ScanResult } from './types.js';

const BARE_HEADERS = {
  server: 'nginx/1.27.5',
  'x-powered-by': 'PHP/7.4.3',
};

/** A site where nothing accepted the https:// connection, but http:// answered 200. */
function plainOnlyScan(
  headers: Record<string, string | string[]> = BARE_HEADERS,
  cookies: CookieInfo[] = [],
  httpsError: HttpErrorCode = 'CONNECTION_FAILED',
): ScanResult {
  const base = makeScan();
  return {
    ...base,
    http: {
      startUrl: 'https://example.com/',
      finalUrl: null,
      hops: [],
      error: { code: httpsError, message: 'https check failed' },
    },
    httpPlain: {
      startUrl: 'http://example.com/',
      finalUrl: 'http://example.com/',
      hops: [
        {
          url: 'http://example.com/',
          status: 200,
          headers,
          cookies,
          remoteIp: '93.184.216.34',
          timingMs: 40,
        },
      ],
      error: null,
    },
  };
}

const ids = (findings: { ruleId: string }[]): string[] => findings.map((f) => f.ruleId);

describe('judgedChain: plain-HTTP fallback', () => {
  it('uses the https chain when it worked', () => {
    const scan = makeScan();

    expect(judgedChain(scan)).toBe(scan.http);
  });

  it('falls back to the plain chain when https was refused and http answered', () => {
    const scan = plainOnlyScan();

    expect(judgedChain(scan)).toBe(scan.httpPlain);
    expect(finalHop(scan)?.url).toBe('http://example.com/');
  });

  it.each(['TIMEOUT', 'TLS_ERROR', 'BLOCKED_TARGET', 'UNKNOWN'] as const)(
    'does not fall back when https failed with %s',
    (code) => {
      expect(judgedChain(plainOnlyScan(BARE_HEADERS, [], code))).toBeNull();
    },
  );

  it('does not fall back when the plain check also failed', () => {
    const scan = plainOnlyScan();
    const broken: ScanResult = {
      ...scan,
      httpPlain: { ...scan.httpPlain, error: { code: 'TIMEOUT', message: 'slow' } },
    };

    expect(judgedChain(broken)).toBeNull();
  });

  it('does not fall back when the plain check has no responses', () => {
    const scan = plainOnlyScan();
    const empty: ScanResult = { ...scan, httpPlain: { ...scan.httpPlain, hops: [] } };

    expect(judgedChain(empty)).toBeNull();
  });
});

describe('rules on a site that only answers on plain HTTP', () => {
  it('reports missing headers against the http:// URL', () => {
    const findings = headerRules(plainOnlyScan());

    expect(ids(findings)).toEqual(
      expect.arrayContaining([
        RULE_IDS.HTTP_CSP_MISSING,
        RULE_IDS.HTTP_CONTENT_TYPE_OPTIONS_MISSING,
        RULE_IDS.HTTP_FRAME_PROTECTION_MISSING,
        RULE_IDS.HTTP_REFERRER_POLICY_MISSING,
      ]),
    );
    for (const finding of findings) {
      expect(finding.evidence).toMatchObject({ url: 'http://example.com/' });
    }
  });

  it('does not judge HSTS, which only applies to https responses', () => {
    expect(ids(headerRules(plainOnlyScan()))).not.toContain(RULE_IDS.HTTP_HSTS_MISSING);
  });

  it('reports version disclosure in Server and X-Powered-By', () => {
    const findings = disclosureRules(plainOnlyScan());

    expect(ids(findings).sort()).toEqual(
      [RULE_IDS.HTTP_SERVER_VERSION_DISCLOSED, RULE_IDS.HTTP_POWERED_BY_DISCLOSED].sort(),
    );
    expect(findings[0]?.evidence).toMatchObject({ url: 'http://example.com/' });
  });

  it('judges cookie flags, but not Secure, on a plain response', () => {
    const cookie: CookieInfo = { name: 'sid', secure: false, httpOnly: false, sameSite: null };
    const found = ids(cookieRules(plainOnlyScan(BARE_HEADERS, [cookie])));

    expect(found).toContain(RULE_IDS.COOKIE_HTTPONLY_MISSING);
    expect(found).toContain(RULE_IDS.COOKIE_SAMESITE_MISSING);
    expect(found).not.toContain(RULE_IDS.COOKIE_SECURE_MISSING);
  });

  it.each(['TIMEOUT', 'TLS_ERROR', 'BLOCKED_TARGET'] as const)(
    'stays silent when https failed with %s',
    (code) => {
      const scan = plainOnlyScan(BARE_HEADERS, [], code);

      expect(headerRules(scan)).toEqual([]);
      expect(disclosureRules(scan)).toEqual([]);
      expect(cookieRules(scan)).toEqual([]);
    },
  );
});
