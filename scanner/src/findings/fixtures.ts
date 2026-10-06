import type { ScanResult } from './types.js';

/** A response with every security header present. */
export const CLEAN_HEADERS: Record<string, string | string[]> = {
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'strict-origin-when-cross-origin',
};

/**
 * A scan result that should produce zero findings.
 * Tests override only the part they want to check.
 */
export function makeScan(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    target: 'example.com',
    dns: {
      hostname: 'example.com',
      a: { ok: true, records: ['93.184.216.34'] },
      aaaa: { ok: true, records: [] },
      mx: { ok: true, records: [] },
      ns: { ok: true, records: ['ns1.example.com'] },
      txt: { ok: true, records: ['v=spf1 -all'] },
      caa: { ok: true, records: [{ critical: false, tag: 'issue', value: 'letsencrypt.org' }] },
      dmarcTxt: { ok: true, records: ['v=DMARC1; p=reject'] },
      spf: { raw: 'v=spf1 -all', all: '-all' },
      dmarc: { raw: 'v=DMARC1; p=reject', policy: 'reject' },
    },
    http: {
      startUrl: 'https://example.com/',
      finalUrl: 'https://example.com/',
      hops: [
        {
          url: 'https://example.com/',
          status: 200,
          headers: { ...CLEAN_HEADERS },
          cookies: [],
          remoteIp: '93.184.216.34',
          timingMs: 50,
        },
      ],
      error: null,
    },
    httpPlain: {
      startUrl: 'http://example.com/',
      finalUrl: 'https://example.com/',
      hops: [
        {
          url: 'http://example.com/',
          status: 301,
          headers: { location: 'https://example.com/' },
          cookies: [],
          remoteIp: '93.184.216.34',
          timingMs: 40,
        },
        {
          url: 'https://example.com/',
          status: 200,
          headers: { ...CLEAN_HEADERS },
          cookies: [],
          remoteIp: '93.184.216.34',
          timingMs: 50,
        },
      ],
      error: null,
    },
    tcp: { ok: true, result: { ip: '93.184.216.34', ports: [] } },
    tls: {
      ok: true,
      result: {
        ip: '93.184.216.34',
        protocol: 'TLSv1.3',
        cipher: 'TLS_AES_256_GCM_SHA384',
        certificate: {
          subject: { commonName: 'example.com', organization: null },
          issuer: { commonName: 'Some CA', organization: 'Some Org' },
          san: ['example.com'],
          validFrom: '2026-01-01T00:00:00.000Z',
          validTo: '2027-01-01T00:00:00.000Z',
          serialNumber: '01',
          fingerprint256: 'AA:BB',
        },
        analysis: { expired: false, daysUntilExpiry: 90, selfSigned: false, hostnameMatches: true },
      },
    },
    ...overrides,
  };
}

/** A clean scan whose final response has exactly these headers. */
export function scanWithHeaders(headers: Record<string, string | string[]>): ScanResult {
  const base = makeScan();
  const hop = base.http.hops[0];
  if (hop === undefined) throw new Error('fixture has no hop');
  return { ...base, http: { ...base.http, hops: [{ ...hop, headers }] } };
}
