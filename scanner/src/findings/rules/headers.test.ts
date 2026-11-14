import { describe, expect, it } from 'vitest';
import { CLEAN_HEADERS, makeScan, scanWithHeaders } from '../fixtures.js';
import { RULE_IDS } from '../ids.js';
import { headerRules } from './headers.js';

const ids = (scan: Parameters<typeof headerRules>[0]): string[] =>
  headerRules(scan).map((f) => f.ruleId);

describe('headerRules', () => {
  it('produces nothing when every header is present', () => {
    expect(headerRules(makeScan())).toEqual([]);
  });

  it('reports every missing header with evidence and remediation', () => {
    const findings = headerRules(scanWithHeaders({}));

    expect(findings.map((f) => f.ruleId).sort()).toEqual(
      [
        RULE_IDS.HTTP_CSP_MISSING,
        RULE_IDS.HTTP_HSTS_MISSING,
        RULE_IDS.HTTP_CONTENT_TYPE_OPTIONS_MISSING,
        RULE_IDS.HTTP_FRAME_PROTECTION_MISSING,
        RULE_IDS.HTTP_REFERRER_POLICY_MISSING,
      ].sort(),
    );
    for (const finding of findings) {
      expect(finding.severity).toBe('low');
      expect(Object.keys(finding.evidence).length).toBeGreaterThan(0);
      expect(finding.remediation).not.toBe('');
    }
  });

  it('never claims a vulnerability', () => {
    for (const finding of headerRules(scanWithHeaders({}))) {
      expect(`${finding.title} ${finding.description}`.toLowerCase()).not.toContain('vulnerab');
    }
  });

  it('matches a snapshot for a bare response', () => {
    expect(headerRules(scanWithHeaders({}))).toMatchSnapshot();
  });

  it('reports only the one header that is missing', () => {
    const { 'referrer-policy': _removed, ...rest } = CLEAN_HEADERS;

    expect(ids(scanWithHeaders(rest))).toEqual([RULE_IDS.HTTP_REFERRER_POLICY_MISSING]);
  });

  it('does not judge HSTS on a plain HTTP response', () => {
    const scan = scanWithHeaders({ ...CLEAN_HEADERS });
    const { 'strict-transport-security': _removed, ...rest } = CLEAN_HEADERS;
    const http = {
      ...scan.http,
      hops: [{ ...scan.http.hops[0]!, url: 'http://example.com/', headers: rest }],
    };

    expect(ids({ ...scan, http })).not.toContain(RULE_IDS.HTTP_HSTS_MISSING);
  });

  it('accepts CSP frame-ancestors instead of X-Frame-Options', () => {
    const { 'x-frame-options': _removed, ...rest } = CLEAN_HEADERS;

    expect(ids(scanWithHeaders(rest))).toEqual([]);
  });

  it('reports frame protection when neither is present', () => {
    const { 'x-frame-options': _a, ...rest } = CLEAN_HEADERS;

    expect(
      ids(
        scanWithHeaders({
          ...rest,
          'content-security-policy': "default-src 'self'; base-uri 'self'",
        }),
      ),
    ).toEqual([RULE_IDS.HTTP_FRAME_PROTECTION_MISSING]);
  });

  it('does not mistake a similar directive for frame-ancestors', () => {
    const { 'x-frame-options': _a, ...rest } = CLEAN_HEADERS;

    expect(
      ids(
        scanWithHeaders({
          ...rest,
          'content-security-policy':
            "default-src 'self'; base-uri 'self'; x-frame-ancestors 'none'",
        }),
      ),
    ).toEqual([RULE_IDS.HTTP_FRAME_PROTECTION_MISSING]);
  });

  it('flags X-Content-Type-Options with a value other than nosniff', () => {
    const findings = headerRules(
      scanWithHeaders({ ...CLEAN_HEADERS, 'x-content-type-options': 'sniff' }),
    );

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.HTTP_CONTENT_TYPE_OPTIONS_MISSING]);
    expect(findings[0]?.evidence).toMatchObject({ present: true, value: 'sniff' });
  });

  it('flags HSTS with a max-age below 180 days', () => {
    const findings = headerRules(
      scanWithHeaders({ ...CLEAN_HEADERS, 'strict-transport-security': 'max-age=300' }),
    );

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.HTTP_HSTS_WEAK]);
    expect(findings[0]?.evidence).toMatchObject({ maxAgeSeconds: 300 });
  });

  it('flags HSTS with max-age=0', () => {
    expect(
      ids(scanWithHeaders({ ...CLEAN_HEADERS, 'strict-transport-security': 'max-age=0' })),
    ).toEqual([RULE_IDS.HTTP_HSTS_WEAK]);
  });

  it('flags HSTS with no max-age value', () => {
    const findings = headerRules(
      scanWithHeaders({ ...CLEAN_HEADERS, 'strict-transport-security': 'includeSubDomains' }),
    );

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.HTTP_HSTS_WEAK]);
    expect(findings[0]?.evidence).toMatchObject({ maxAgeSeconds: null });
  });

  it('accepts HSTS at exactly 180 days', () => {
    expect(
      ids(
        scanWithHeaders({
          ...CLEAN_HEADERS,
          'strict-transport-security': 'max-age=15552000; includeSubDomains; preload',
        }),
      ),
    ).toEqual([]);
  });

  it('accepts a quoted HSTS max-age', () => {
    expect(
      ids(
        scanWithHeaders({
          ...CLEAN_HEADERS,
          'strict-transport-security': 'max-age="31536000"; includeSubDomains; preload',
        }),
      ),
    ).toEqual([]);
  });

  it('notes HSTS without includeSubDomains', () => {
    const findings = headerRules(
      scanWithHeaders({
        ...CLEAN_HEADERS,
        'strict-transport-security': 'max-age=31536000; preload',
      }),
    );

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.HTTP_HSTS_NO_INCLUDE_SUBDOMAINS]);
    expect(findings[0]?.severity).toBe('informational');
  });

  it('notes HSTS without preload', () => {
    const findings = headerRules(
      scanWithHeaders({
        ...CLEAN_HEADERS,
        'strict-transport-security': 'max-age=31536000; includeSubDomains',
      }),
    );

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.HTTP_HSTS_NO_PRELOAD]);
    expect(findings[0]?.severity).toBe('informational');
  });

  it('matches directive names in any letter case', () => {
    expect(
      ids(
        scanWithHeaders({
          ...CLEAN_HEADERS,
          'strict-transport-security': 'max-age=31536000; INCLUDESUBDOMAINS; Preload',
        }),
      ),
    ).toEqual([]);
  });

  it('reports a short max-age once and adds no directive findings', () => {
    expect(
      ids(scanWithHeaders({ ...CLEAN_HEADERS, 'strict-transport-security': 'max-age=300' })),
    ).toEqual([RULE_IDS.HTTP_HSTS_WEAK]);
  });

  it('does not judge HSTS strength on a plain HTTP response', () => {
    const scan = scanWithHeaders({ ...CLEAN_HEADERS, 'strict-transport-security': 'max-age=0' });
    const http = {
      ...scan.http,
      hops: [{ ...scan.http.hops[0]!, url: 'http://example.com/' }],
    };

    expect(ids({ ...scan, http })).not.toContain(RULE_IDS.HTTP_HSTS_WEAK);
  });

  it("flags 'unsafe-inline' in script-src", () => {
    const findings = headerRules(
      scanWithHeaders({
        ...CLEAN_HEADERS,
        'content-security-policy':
          "script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
      }),
    );

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.HTTP_CSP_WEAK]);
    expect(findings[0]?.evidence).toMatchObject({
      directive: 'script-src',
      weakSources: ["'unsafe-inline'"],
    });
  });

  it("flags 'unsafe-eval' in script-src", () => {
    expect(
      ids(
        scanWithHeaders({
          ...CLEAN_HEADERS,
          'content-security-policy':
            "script-src 'self' 'unsafe-eval'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        }),
      ),
    ).toEqual([RULE_IDS.HTTP_CSP_WEAK]);
  });

  it('flags a bare wildcard in script-src', () => {
    expect(
      ids(
        scanWithHeaders({
          ...CLEAN_HEADERS,
          'content-security-policy':
            "script-src *; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        }),
      ),
    ).toEqual([RULE_IDS.HTTP_CSP_WEAK]);
  });

  it('does not flag a wildcard subdomain', () => {
    expect(
      ids(
        scanWithHeaders({
          ...CLEAN_HEADERS,
          'content-security-policy':
            "script-src *.example.com; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        }),
      ),
    ).toEqual([]);
  });

  it('falls back to default-src when script-src is absent', () => {
    const findings = headerRules(
      scanWithHeaders({
        ...CLEAN_HEADERS,
        'content-security-policy':
          "default-src 'self' 'unsafe-inline'; base-uri 'self'; frame-ancestors 'none'",
      }),
    );

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.HTTP_CSP_WEAK]);
    expect(findings[0]?.evidence).toMatchObject({ directive: 'default-src' });
  });

  it('lets script-src override a weak default-src', () => {
    expect(
      ids(
        scanWithHeaders({
          ...CLEAN_HEADERS,
          'content-security-policy':
            "default-src *; script-src 'self'; base-uri 'self'; frame-ancestors 'none'",
        }),
      ),
    ).toEqual([]);
  });

  it("does not flag 'unsafe-inline' outside script directives", () => {
    expect(
      ids(
        scanWithHeaders({
          ...CLEAN_HEADERS,
          'content-security-policy':
            "script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        }),
      ),
    ).toEqual([]);
  });

  it("does not flag 'unsafe-inline' when a nonce is present", () => {
    expect(
      ids(
        scanWithHeaders({
          ...CLEAN_HEADERS,
          'content-security-policy':
            "script-src 'nonce-abc123' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        }),
      ),
    ).toEqual([]);
  });

  it("still flags 'unsafe-eval' when a nonce is present", () => {
    expect(
      ids(
        scanWithHeaders({
          ...CLEAN_HEADERS,
          'content-security-policy':
            "script-src 'nonce-abc123' 'unsafe-eval'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        }),
      ),
    ).toEqual([RULE_IDS.HTTP_CSP_WEAK]);
  });

  it('uses the first occurrence of a duplicated directive', () => {
    expect(
      ids(
        scanWithHeaders({
          ...CLEAN_HEADERS,
          'content-security-policy':
            "script-src 'self'; script-src 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        }),
      ),
    ).toEqual([]);
  });

  it('notes a CSP with neither object-src nor default-src', () => {
    const findings = headerRules(
      scanWithHeaders({
        ...CLEAN_HEADERS,
        'content-security-policy': "script-src 'self'; base-uri 'self'; frame-ancestors 'none'",
      }),
    );

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.HTTP_CSP_NO_OBJECT_SRC]);
    expect(findings[0]?.severity).toBe('informational');
  });

  it('accepts default-src as the fallback for object-src', () => {
    expect(
      ids(
        scanWithHeaders({
          ...CLEAN_HEADERS,
          'content-security-policy': "default-src 'self'; base-uri 'self'; frame-ancestors 'none'",
        }),
      ),
    ).toEqual([]);
  });

  it('accepts an explicit object-src without default-src', () => {
    expect(
      ids(
        scanWithHeaders({
          ...CLEAN_HEADERS,
          'content-security-policy':
            "script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        }),
      ),
    ).toEqual([]);
  });

  it('notes a CSP without base-uri even when default-src is set', () => {
    const findings = headerRules(
      scanWithHeaders({
        ...CLEAN_HEADERS,
        'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
      }),
    );

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.HTTP_CSP_NO_BASE_URI]);
    expect(findings[0]?.severity).toBe('informational');
  });

  it('produces nothing when the HTTP check failed', () => {
    const scan = makeScan();
    const http = { ...scan.http, error: { code: 'TIMEOUT' as const, message: 'slow' } };

    expect(headerRules({ ...scan, http })).toEqual([]);
  });

  it('produces nothing when there were no hops', () => {
    const scan = makeScan();

    expect(headerRules({ ...scan, http: { ...scan.http, hops: [] } })).toEqual([]);
  });
});
