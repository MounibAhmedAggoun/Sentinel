import { describe, expect, it, vi } from 'vitest';
import type { ResolveResult } from '@sentinel/core';
import { parseSan } from './connect.js';
import { scanTls } from './scan.js';
import type { TlsOutcome } from './types.js';

const PUBLIC_IP = '93.184.216.34';

const allow = (host: string): Promise<ResolveResult> =>
  Promise.resolve({ allowed: true, hostname: host, ips: [PUBLIC_IP] });

const okOutcome: TlsOutcome = {
  ok: true,
  result: {
    ip: PUBLIC_IP,
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
};

describe('scanTls', () => {
  it('connects to the validated IP, using the hostname for the name check', async () => {
    const connect = vi.fn().mockResolvedValue(okOutcome);

    const outcome = await scanTls('example.com', { resolve: allow, connect });

    expect(outcome).toEqual(okOutcome);
    expect(connect).toHaveBeenCalledWith({
      hostname: 'example.com',
      ip: PUBLIC_IP,
      port: 443,
      timeoutMs: 5000,
    });
  });

  it('does not connect when net-guard blocks the target', async () => {
    const resolve = (): Promise<ResolveResult> =>
      Promise.resolve({ allowed: false, reason: 'blocked address range: private' });
    const connect = vi.fn();

    const outcome = await scanTls('internal.test', { resolve, connect });

    expect(outcome).toEqual({
      ok: false,
      error: { code: 'BLOCKED_TARGET', message: 'blocked address range: private' },
    });
    expect(connect).not.toHaveBeenCalled();
  });

  it('passes through connection errors', async () => {
    const error: TlsOutcome = { ok: false, error: { code: 'TIMEOUT', message: 'slow' } };
    const connect = vi.fn().mockResolvedValue(error);

    expect(await scanTls('example.com', { resolve: allow, connect })).toEqual(error);
  });
});

describe('parseSan', () => {
  it('extracts DNS names and IP addresses', () => {
    expect(parseSan('DNS:example.com, DNS:*.example.com, IP Address:93.184.216.34')).toEqual([
      'example.com',
      '*.example.com',
      '93.184.216.34',
    ]);
  });

  it('ignores other entry types', () => {
    expect(parseSan('email:a@example.com, URI:https://example.com, DNS:example.com')).toEqual([
      'example.com',
    ]);
  });

  it('returns an empty list for missing input', () => {
    expect(parseSan(undefined)).toEqual([]);
    expect(parseSan('')).toEqual([]);
  });
});
