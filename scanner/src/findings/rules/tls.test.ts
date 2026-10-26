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
    trust: { authorized: boolean; error: string | null };
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

  it('reports an untrusted certificate when nothing else explains it', () => {
    const findings = tlsRules(
      withAnalysis({ trust: { authorized: false, error: 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY' } }),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: RULE_IDS.TLS_CERT_NOT_TRUSTED,
      severity: 'medium',
      evidence: { reason: 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY' },
    });
    expect(findings[0]?.remediation).not.toBe('');
  });

  it('does not report "not trusted" separately when the certificate is already self-signed', () => {
    const findings = tlsRules(
      withAnalysis({
        selfSigned: true,
        trust: { authorized: false, error: 'DEPTH_ZERO_SELF_SIGNED_CERT' },
      }),
    );

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.TLS_CERT_SELF_SIGNED]);
  });

  it('does not report "not trusted" separately when the certificate is already expired', () => {
    const findings = tlsRules(
      withAnalysis({
        expired: true,
        daysUntilExpiry: -5,
        trust: { authorized: false, error: 'CERT_HAS_EXPIRED' },
      }),
    );

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.TLS_CERT_EXPIRED]);
  });

  it('does not report "not trusted" when the certificate is authorized', () => {
    const findings = tlsRules(withAnalysis({ trust: { authorized: true, error: null } }));

    expect(findings).toEqual([]);
  });

  it('produces nothing for legacy protocols when the probe did not run', () => {
    const findings = tlsRules(makeScan());

    expect(findings.map((f) => f.ruleId)).not.toContain(RULE_IDS.TLS_LEGACY_PROTOCOL_ACCEPTED);
    expect(findings.map((f) => f.ruleId)).not.toContain(RULE_IDS.TLS_1_3_NOT_SUPPORTED);
  });

  it('reports accepted legacy protocol versions', () => {
    const base = makeScan();
    if (!base.tls.ok) throw new Error('fixture TLS should be ok');
    const scan = {
      ...base,
      tls: {
        ok: true as const,
        result: {
          ...base.tls.result,
          legacyProtocols: {
            acceptedLegacyVersions: ['TLSv1.1'] as ('TLSv1' | 'TLSv1.1')[],
            missingTls13: false,
          },
        },
      },
    };

    const findings = tlsRules(scan);

    expect(findings.map((f) => f.ruleId)).toContain(RULE_IDS.TLS_LEGACY_PROTOCOL_ACCEPTED);
    const finding = findings.find((f) => f.ruleId === RULE_IDS.TLS_LEGACY_PROTOCOL_ACCEPTED);
    expect(finding?.severity).toBe('medium');
    expect(finding?.evidence).toEqual({ acceptedVersions: ['TLSv1.1'] });
  });

  it('reports missing TLS 1.3 support as informational', () => {
    const base = makeScan();
    if (!base.tls.ok) throw new Error('fixture TLS should be ok');
    const scan = {
      ...base,
      tls: {
        ok: true as const,
        result: {
          ...base.tls.result,
          legacyProtocols: { acceptedLegacyVersions: [], missingTls13: true },
        },
      },
    };

    const findings = tlsRules(scan);

    const finding = findings.find((f) => f.ruleId === RULE_IDS.TLS_1_3_NOT_SUPPORTED);
    expect(finding?.severity).toBe('informational');
  });

  it('produces nothing for legacy protocols when none are accepted and TLS 1.3 is supported', () => {
    const base = makeScan();
    if (!base.tls.ok) throw new Error('fixture TLS should be ok');
    const scan = {
      ...base,
      tls: {
        ok: true as const,
        result: {
          ...base.tls.result,
          legacyProtocols: { acceptedLegacyVersions: [], missingTls13: false },
        },
      },
    };

    const findings = tlsRules(scan);

    expect(findings.map((f) => f.ruleId)).not.toContain(RULE_IDS.TLS_LEGACY_PROTOCOL_ACCEPTED);
    expect(findings.map((f) => f.ruleId)).not.toContain(RULE_IDS.TLS_1_3_NOT_SUPPORTED);
  });
});
