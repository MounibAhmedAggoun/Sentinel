import { describe, expect, it } from 'vitest';
import { makeScan, scanWithHeaders } from '../fixtures.js';
import { RULE_IDS } from '../ids.js';
import { disclosureRules } from './disclosure.js';

describe('disclosureRules', () => {
  it('produces nothing for a clean response', () => {
    expect(disclosureRules(makeScan())).toEqual([]);
  });

  it('ignores a Server header with no version', () => {
    expect(disclosureRules(scanWithHeaders({ server: 'cloudflare' }))).toEqual([]);
    expect(disclosureRules(scanWithHeaders({ server: 'nginx' }))).toEqual([]);
  });

  it('reports a Server header that includes a version', () => {
    const findings = disclosureRules(scanWithHeaders({ server: 'Apache/2.4.41 (Ubuntu)' }));

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: RULE_IDS.HTTP_SERVER_VERSION_DISCLOSED,
      severity: 'informational',
      evidence: { header: 'Server', value: 'Apache/2.4.41 (Ubuntu)' },
    });
    expect(findings[0]?.remediation).not.toBe('');
  });

  it('reports an X-Powered-By header that includes a version', () => {
    const findings = disclosureRules(scanWithHeaders({ 'x-powered-by': 'PHP/8.1.2' }));

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.HTTP_POWERED_BY_DISCLOSED]);
  });

  it('ignores an X-Powered-By header with no version', () => {
    expect(disclosureRules(scanWithHeaders({ 'x-powered-by': 'Express' }))).toEqual([]);
  });

  it('reports both headers when both include versions', () => {
    const findings = disclosureRules(
      scanWithHeaders({ server: 'nginx/1.18.0', 'x-powered-by': 'PHP/7.4.3' }),
    );

    expect(findings.map((f) => f.ruleId).sort()).toEqual([
      RULE_IDS.HTTP_SERVER_VERSION_DISCLOSED,
      RULE_IDS.HTTP_POWERED_BY_DISCLOSED,
    ]);
  });

  it('caps long header values in the evidence', () => {
    const long = `Apache/2.4.41 ${'x'.repeat(1000)}`;
    const findings = disclosureRules(scanWithHeaders({ server: long }));

    expect(String(findings[0]?.evidence['value']).length).toBe(200);
  });

  it('keeps hostile header text as plain data', () => {
    const hostile = 'Apache/2.4.41 <img src=x onerror=alert(1)>';
    const findings = disclosureRules(scanWithHeaders({ server: hostile }));

    expect(findings[0]?.evidence['value']).toBe(hostile);
  });

  it('produces nothing when the HTTP check failed', () => {
    const scan = makeScan();
    const http = { ...scan.http, error: { code: 'TIMEOUT' as const, message: 'slow' } };

    expect(disclosureRules({ ...scan, http })).toEqual([]);
  });
});
