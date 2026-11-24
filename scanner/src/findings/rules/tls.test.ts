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

describe('tlsRules: key, signature and ALPN', () => {
  function withCertificate(
    certificate: Partial<{
      keyType: string | null;
      keyBits: number | null;
      signatureAlgorithm: string | null;
    }>,
    alpnProtocol: string | null = 'h2',
  ): ScanResult {
    const base = makeScan();
    if (!base.tls.ok) throw new Error('fixture TLS should be ok');
    return {
      ...base,
      tls: {
        ok: true,
        result: {
          ...base.tls.result,
          alpnProtocol,
          certificate: { ...base.tls.result.certificate, ...certificate },
        },
      },
    };
  }
  const ids = (scan: ScanResult): string[] => tlsRules(scan).map((f) => f.ruleId);

  it('notes an RSA key shorter than 2048 bits', () => {
    const findings = tlsRules(withCertificate({ keyType: 'rsa', keyBits: 1024 }));

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.TLS_WEAK_RSA_KEY]);
    expect(findings[0]).toMatchObject({
      severity: 'medium',
      evidence: { keyType: 'rsa', keyBits: 1024, minimumBits: 2048 },
    });
  });

  it('accepts an RSA key of exactly 2048 bits', () => {
    expect(ids(withCertificate({ keyType: 'rsa', keyBits: 2048 }))).toEqual([]);
  });

  it('does not judge a key that is not RSA, or one whose size is unknown', () => {
    expect(ids(withCertificate({ keyType: 'ec', keyBits: null }))).toEqual([]);
    expect(ids(withCertificate({ keyType: 'rsa', keyBits: null }))).toEqual([]);
  });

  it.each(['sha1WithRSAEncryption', 'ecdsa-with-SHA1', 'md5WithRSAEncryption', 'RSA-SHA1'])(
    'notes the weak signature algorithm %s',
    (signatureAlgorithm) => {
      const findings = tlsRules(withCertificate({ signatureAlgorithm }));

      expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.TLS_WEAK_SIGNATURE_ALGORITHM]);
      expect(findings[0]).toMatchObject({ severity: 'medium', evidence: { signatureAlgorithm } });
    },
  );

  it.each([
    'sha256WithRSAEncryption',
    'sha384WithRSAEncryption',
    'sha512WithRSAEncryption',
    'ecdsa-with-SHA256',
    'ecdsa-with-SHA384',
  ])('accepts the signature algorithm %s', (signatureAlgorithm) => {
    expect(ids(withCertificate({ signatureAlgorithm }))).toEqual([]);
  });

  it('does not judge a signature algorithm that could not be read', () => {
    expect(ids(withCertificate({ signatureAlgorithm: null }))).toEqual([]);
  });

  it('accepts a server that chose HTTP/2', () => {
    expect(ids(withCertificate({}, 'h2'))).toEqual([]);
  });

  it('notes a server that chose no application protocol', () => {
    const findings = tlsRules(withCertificate({}, null));

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.TLS_HTTP2_NOT_OFFERED]);
    expect(findings[0]).toMatchObject({
      severity: 'informational',
      evidence: { alpnProtocol: null },
    });
  });

  it('notes a server that chose HTTP/1.1 and says so', () => {
    const findings = tlsRules(withCertificate({}, 'http/1.1'));

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.TLS_HTTP2_NOT_OFFERED]);
    expect(findings[0]?.description).toContain('http/1.1');
  });
});

describe('tlsRules: validity period', () => {
  function withDates(
    validFrom: string,
    validTo: string,
    analysis: Partial<{
      selfSigned: boolean;
      trust: { authorized: boolean; error: string | null };
    }> = {},
  ): ScanResult {
    const base = makeScan();
    if (!base.tls.ok) throw new Error('fixture TLS should be ok');
    return {
      ...base,
      tls: {
        ok: true,
        result: {
          ...base.tls.result,
          certificate: { ...base.tls.result.certificate, validFrom, validTo },
          analysis: { ...base.tls.result.analysis, ...analysis },
        },
      },
    };
  }
  const ids = (scan: ScanResult): string[] => tlsRules(scan).map((f) => f.ruleId);

  it('notes a certificate issued in 2026 that is valid for 201 days', () => {
    const findings = tlsRules(withDates('2026-03-15T00:00:00.000Z', '2026-10-02T00:00:00.000Z'));

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.TLS_VALIDITY_TOO_LONG]);
    expect(findings[0]).toMatchObject({
      severity: 'informational',
      evidence: { validityDays: 201, maximumDays: 200 },
    });
  });

  it('accepts a certificate valid for exactly 200 days', () => {
    expect(ids(withDates('2026-03-15T00:00:00.000Z', '2026-10-01T00:00:00.000Z'))).toEqual([]);
  });

  it('does not judge a certificate issued before 2026-03-15', () => {
    expect(ids(withDates('2026-03-14T00:00:00.000Z', '2027-04-16T00:00:00.000Z'))).toEqual([]);
  });

  it('uses the 100 day limit for certificates issued from 2027-03-15', () => {
    expect(ids(withDates('2027-03-15T00:00:00.000Z', '2027-06-24T00:00:00.000Z'))).toEqual([
      RULE_IDS.TLS_VALIDITY_TOO_LONG,
    ]);
    expect(ids(withDates('2027-03-15T00:00:00.000Z', '2027-06-23T00:00:00.000Z'))).toEqual([]);
  });

  it('uses the 47 day limit for certificates issued from 2029-03-15', () => {
    expect(ids(withDates('2029-03-15T00:00:00.000Z', '2029-05-02T00:00:00.000Z'))).toEqual([
      RULE_IDS.TLS_VALIDITY_TOO_LONG,
    ]);
    expect(ids(withDates('2029-03-15T00:00:00.000Z', '2029-05-01T00:00:00.000Z'))).toEqual([]);
  });

  it('skips self-signed certificates', () => {
    const scan = withDates('2026-03-15T00:00:00.000Z', '2030-03-15T00:00:00.000Z', {
      selfSigned: true,
    });

    expect(ids(scan)).not.toContain(RULE_IDS.TLS_VALIDITY_TOO_LONG);
  });

  it('skips certificates the system trust store did not accept', () => {
    const scan = withDates('2026-03-15T00:00:00.000Z', '2030-03-15T00:00:00.000Z', {
      trust: { authorized: false, error: 'unable to get local issuer certificate' },
    });

    expect(ids(scan)).not.toContain(RULE_IDS.TLS_VALIDITY_TOO_LONG);
  });

  it('does not judge a certificate whose dates cannot be read', () => {
    expect(ids(withDates('garbage', '2030-03-15T00:00:00.000Z'))).toEqual([]);
  });
});
