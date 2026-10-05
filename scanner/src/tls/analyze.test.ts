import { describe, expect, it } from 'vitest';
import { analyzeCertificate, type AnalysisInput } from './analyze.js';

const NOW = new Date('2026-10-01T00:00:00Z');

function input(overrides: Partial<AnalysisInput> = {}): AnalysisInput {
  return {
    hostname: 'example.com',
    validTo: '2027-01-01T00:00:00.000Z',
    subjectRaw: 'CN=example.com',
    issuerRaw: 'CN=Some CA',
    commonName: 'example.com',
    san: ['example.com', 'www.example.com'],
    ...overrides,
  };
}

describe('analyzeCertificate: expiry', () => {
  it('is valid with the right number of days left', () => {
    const result = analyzeCertificate(input({ validTo: '2026-10-31T00:00:00.000Z' }), NOW);

    expect(result.expired).toBe(false);
    expect(result.daysUntilExpiry).toBe(30);
  });

  it('flags an expired certificate with negative days', () => {
    const result = analyzeCertificate(input({ validTo: '2026-09-21T00:00:00.000Z' }), NOW);

    expect(result.expired).toBe(true);
    expect(result.daysUntilExpiry).toBe(-10);
  });

  it('rounds partial days down', () => {
    const result = analyzeCertificate(input({ validTo: '2026-10-08T12:00:00.000Z' }), NOW);

    expect(result.daysUntilExpiry).toBe(7);
  });

  it('treats an unparseable date as expired', () => {
    const result = analyzeCertificate(input({ validTo: 'garbage' }), NOW);

    expect(result.expired).toBe(true);
  });
});

describe('analyzeCertificate: self-signed', () => {
  it('detects subject equal to issuer', () => {
    const result = analyzeCertificate(
      input({ subjectRaw: 'CN=example.com', issuerRaw: 'CN=example.com' }),
      NOW,
    );

    expect(result.selfSigned).toBe(true);
  });

  it('is false when issued by a different authority', () => {
    expect(analyzeCertificate(input(), NOW).selfSigned).toBe(false);
  });

  it('is false when the subject is empty', () => {
    const result = analyzeCertificate(input({ subjectRaw: '', issuerRaw: '' }), NOW);

    expect(result.selfSigned).toBe(false);
  });
});

describe('analyzeCertificate: hostname match', () => {
  it('matches an exact SAN', () => {
    expect(analyzeCertificate(input(), NOW).hostnameMatches).toBe(true);
  });

  it('matches a wildcard for one label', () => {
    const result = analyzeCertificate(
      input({ hostname: 'www.example.com', san: ['*.example.com'] }),
      NOW,
    );

    expect(result.hostnameMatches).toBe(true);
  });

  it('does not match a wildcard for the bare domain', () => {
    const result = analyzeCertificate(input({ san: ['*.example.com'] }), NOW);

    expect(result.hostnameMatches).toBe(false);
  });

  it('does not match a wildcard across two labels', () => {
    const result = analyzeCertificate(
      input({ hostname: 'a.b.example.com', san: ['*.example.com'] }),
      NOW,
    );

    expect(result.hostnameMatches).toBe(false);
  });

  it('detects a certificate for a different name', () => {
    const result = analyzeCertificate(
      input({ hostname: 'other.com', san: ['example.com'], commonName: 'example.com' }),
      NOW,
    );

    expect(result.hostnameMatches).toBe(false);
  });

  it('matches an IP address listed in the SAN', () => {
    const result = analyzeCertificate(
      input({ hostname: '93.184.216.34', san: ['93.184.216.34'], commonName: null }),
      NOW,
    );

    expect(result.hostnameMatches).toBe(true);
  });

  it('does not match when the certificate has no names at all', () => {
    const result = analyzeCertificate(input({ san: [], commonName: null }), NOW);

    expect(result.hostnameMatches).toBe(false);
  });
});
