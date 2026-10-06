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
      ids(scanWithHeaders({ ...rest, 'content-security-policy': "default-src 'self'" })),
    ).toEqual([RULE_IDS.HTTP_FRAME_PROTECTION_MISSING]);
  });

  it('does not mistake a similar directive for frame-ancestors', () => {
    const { 'x-frame-options': _a, ...rest } = CLEAN_HEADERS;

    expect(
      ids(
        scanWithHeaders({
          ...rest,
          'content-security-policy': "default-src 'self'; x-frame-ancestors 'none'",
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
