import { describe, expect, it, vi } from 'vitest';
import { resolveDns, type DnsResolver } from './resolve.js';

function codeError(code: string): Error {
  return Object.assign(new Error(code), { code });
}

function fakeResolver(overrides: Partial<Record<keyof DnsResolver, unknown>> = {}): DnsResolver {
  const notFound = () => Promise.reject(codeError('ENOTFOUND'));
  return {
    resolve4: vi.fn(notFound),
    resolve6: vi.fn(notFound),
    resolveMx: vi.fn(notFound),
    resolveNs: vi.fn(notFound),
    resolveTxt: vi.fn(notFound),
    resolveCaa: vi.fn(notFound),
    ...overrides,
  } as unknown as DnsResolver;
}

describe('resolveDns', () => {
  it('returns normalized records and parsed SPF/DMARC', async () => {
    const resolveTxt = vi.fn((name: string) =>
      Promise.resolve(
        name.startsWith('_dmarc.')
          ? [['v=DMARC1; p=reject']]
          : [['v=spf1 include:example.net -all'], ['hello']],
      ),
    );
    const resolver = fakeResolver({
      resolve4: vi.fn().mockResolvedValue(['93.184.216.34']),
      resolve6: vi.fn().mockResolvedValue(['2606:2800:220:1::1']),
      resolveMx: vi.fn().mockResolvedValue([{ exchange: 'mail.example.com', priority: 10 }]),
      resolveNs: vi.fn().mockResolvedValue(['ns1.example.com']),
      resolveTxt,
      resolveCaa: vi.fn().mockResolvedValue([{ critical: 0, issue: 'letsencrypt.org' }]),
    });

    const result = await resolveDns('example.com', resolver);

    expect(result.a).toEqual({ ok: true, records: ['93.184.216.34'] });
    expect(result.mx).toEqual({
      ok: true,
      records: [{ exchange: 'mail.example.com', priority: 10 }],
    });
    expect(result.caa).toEqual({
      ok: true,
      records: [{ critical: false, tag: 'issue', value: 'letsencrypt.org' }],
    });
    expect(result.spf?.all).toBe('-all');
    expect(result.dmarc?.policy).toBe('reject');
    expect(resolveTxt).toHaveBeenCalledWith('_dmarc.example.com');
  });

  it('turns failures into structured errors instead of throwing', async () => {
    const result = await resolveDns('nope.invalid', fakeResolver());

    expect(result.a).toEqual({ ok: false, error: { code: 'NXDOMAIN', message: 'ENOTFOUND' } });
    expect(result.txt.ok).toBe(false);
    expect(result.spf).toBeNull();
    expect(result.dmarc).toBeNull();
  });

  it('keeps other lookups working when one fails', async () => {
    const resolver = fakeResolver({
      resolve4: vi.fn().mockResolvedValue(['1.2.3.4']),
      resolveMx: vi.fn().mockRejectedValue(codeError('ETIMEOUT')),
      resolveNs: vi.fn().mockRejectedValue(codeError('ESERVFAIL')),
    });

    const result = await resolveDns('example.com', resolver);

    expect(result.a.ok).toBe(true);
    expect(result.mx).toMatchObject({ ok: false, error: { code: 'TIMEOUT' } });
    expect(result.ns).toMatchObject({ ok: false, error: { code: 'SERVFAIL' } });
  });

  it('joins TXT records that were split into chunks', async () => {
    const resolver = fakeResolver({
      resolveTxt: vi.fn().mockResolvedValue([['v=spf1 include:a.com ', '-all']]),
    });

    const result = await resolveDns('example.com', resolver);

    expect(result.txt).toEqual({ ok: true, records: ['v=spf1 include:a.com -all'] });
    expect(result.spf?.all).toBe('-all');
  });

  it('marks a critical CAA record', async () => {
    const resolver = fakeResolver({
      resolveCaa: vi.fn().mockResolvedValue([{ critical: 128, iodef: 'mailto:sec@example.com' }]),
    });

    const result = await resolveDns('example.com', resolver);

    expect(result.caa).toEqual({
      ok: true,
      records: [{ critical: true, tag: 'iodef', value: 'mailto:sec@example.com' }],
    });
  });
});
