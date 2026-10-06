import { describe, expect, it } from 'vitest';
import { makeScan } from '../fixtures.js';
import { RULE_IDS } from '../ids.js';
import type { ScanResult } from '../types.js';
import { tlsRules } from './tls.js';

function withAnalysis(
  analysis: Partial<{
    expired: boolean;
    daysUntilExpiry: number;
    selfSigned: boolean;
    hostnameMatches: boolean;
  }>,
): ScanResult {
  const base = makeScan();
  if (!base.tls.ok) throw new Error('fixture TLS should be ok');
  return {
    ...base,
    tls: {
      ok: true,
      result: { ...base.tls.result, analysis: { ...base.tls.result.analysis, ...analysis } },
    },
  };
}

describe('tlsRules', () => {
  it('produces nothing for a healthy certificate', () => {
    expect(tlsRules(makeScan())).toEqual([]);
  });

  it('reports an expired certificate as high', () => {
    const findings = tlsRules(withAnalysis({ expired: true, daysUntilExpiry: -5 }));

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: RULE_IDS.TLS_CERT_EXPIRED,
      severity: 'high',
      evidence: { daysUntilExpiry: -5 },
    });
    expect(findings[0]?.remediation).not.toBe('');
  });

  it('does not also report "expiring" for an expired certificate', () => {
    const ids = tlsRules(withAnalysis({ expired: true, daysUntilExpiry: -5 })).map((f) => f.ruleId);

    expect(ids).not.toContain(RULE_IDS.TLS_CERT_EXPIRING);
  });

  it.each([
    [31, null],
    [30, 'low'],
    [15, 'low'],
    [14, 'medium'],
    [8, 'medium'],
    [7, 'high'],
    [0, 'high'],
  ])('maps %i days left to severity %s', (days, severity) => {
    const findings = tlsRules(withAnalysis({ daysUntilExpiry: days }));

    if (severity === null) {
      expect(findings).toEqual([]);
    } else {
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({ ruleId: RULE_IDS.TLS_CERT_EXPIRING, severity });
    }
  });

  it('reports a self-signed certificate as medium', () => {
    const findings = tlsRules(withAnalysis({ selfSigned: true }));

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.TLS_CERT_SELF_SIGNED]);
    expect(findings[0]?.severity).toBe('medium');
  });

  it('reports a hostname mismatch with the SAN list as evidence', () => {
    const findings = tlsRules(withAnalysis({ hostnameMatches: false }));

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.TLS_CERT_HOSTNAME_MISMATCH]);
    expect(findings[0]?.evidence).toMatchObject({
      hostname: 'example.com',
      san: ['example.com'],
    });
  });

  it('reports several problems together', () => {
    const findings = tlsRules(
      withAnalysis({
        expired: true,
        daysUntilExpiry: -1,
        selfSigned: true,
        hostnameMatches: false,
      }),
    );

    expect(findings.map((f) => f.ruleId).sort()).toEqual(
      [
        RULE_IDS.TLS_CERT_EXPIRED,
        RULE_IDS.TLS_CERT_SELF_SIGNED,
        RULE_IDS.TLS_CERT_HOSTNAME_MISMATCH,
      ].sort(),
    );
  });

  it('never claims a vulnerability', () => {
    const findings = tlsRules(
      withAnalysis({
        expired: true,
        daysUntilExpiry: -1,
        selfSigned: true,
        hostnameMatches: false,
      }),
    );

    for (const finding of findings) {
      expect(`${finding.title} ${finding.description}`.toLowerCase()).not.toContain('vulnerab');
    }
  });

  it('produces nothing when the TLS check failed', () => {
    const scan: ScanResult = {
      ...makeScan(),
      tls: { ok: false, error: { code: 'TIMEOUT', message: 'slow' } },
    };

    expect(tlsRules(scan)).toEqual([]);
  });
});
