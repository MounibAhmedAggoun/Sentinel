import { describe, expect, it } from 'vitest';
import { makeScan } from '../../scanner/src/findings/fixtures.js';
import { countFailedModules } from './module-failures.js';

const TIMEOUT = { ok: false as const, error: { code: 'TIMEOUT' as const, message: 'slow' } };

describe('countFailedModules', () => {
  it('counts 0 for a fully clean scan', () => {
    expect(countFailedModules(makeScan())).toBe(0);
  });

  it('does not count DNS as failed when only some lookups errored', () => {
    const base = makeScan();
    const scan = { ...base, dns: { ...base.dns, mx: TIMEOUT, ns: TIMEOUT, caa: TIMEOUT } };

    expect(countFailedModules(scan)).toBe(0);
  });

  it('counts DNS as one failure only when every lookup errored', () => {
    const base = makeScan();
    const scan = {
      ...base,
      dns: {
        ...base.dns,
        a: TIMEOUT,
        aaaa: TIMEOUT,
        mx: TIMEOUT,
        ns: TIMEOUT,
        txt: TIMEOUT,
        caa: TIMEOUT,
        dmarcTxt: TIMEOUT,
      },
    };

    expect(countFailedModules(scan)).toBe(1);
  });

  it('counts http, httpPlain, tcp and tls independently', () => {
    const base = makeScan();
    const scan = {
      ...base,
      http: { ...base.http, error: { code: 'TIMEOUT' as const, message: 'slow' } },
      httpPlain: { ...base.httpPlain, error: { code: 'TIMEOUT' as const, message: 'slow' } },
      tcp: { ok: false as const, error: { code: 'BLOCKED_TARGET' as const, message: 'blocked' } },
      tls: { ok: false as const, error: { code: 'TIMEOUT' as const, message: 'slow' } },
    };

    expect(countFailedModules(scan)).toBe(4);
  });

  it('counts all 5 when everything failed', () => {
    const base = makeScan();
    const scan = {
      ...base,
      dns: {
        ...base.dns,
        a: TIMEOUT,
        aaaa: TIMEOUT,
        mx: TIMEOUT,
        ns: TIMEOUT,
        txt: TIMEOUT,
        caa: TIMEOUT,
        dmarcTxt: TIMEOUT,
      },
      http: { ...base.http, error: { code: 'TIMEOUT' as const, message: 'slow' } },
      httpPlain: { ...base.httpPlain, error: { code: 'TIMEOUT' as const, message: 'slow' } },
      tcp: { ok: false as const, error: { code: 'BLOCKED_TARGET' as const, message: 'blocked' } },
      tls: { ok: false as const, error: { code: 'TIMEOUT' as const, message: 'slow' } },
    };

    expect(countFailedModules(scan)).toBe(5);
  });
});
