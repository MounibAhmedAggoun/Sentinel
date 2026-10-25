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

  it('falls back to the organizational domain for DMARC when the subdomain has none', async () => {
    const resolveTxt = vi.fn((name: string) => {
      if (name === '_dmarc.www.example.com') return Promise.reject(codeError('ENODATA'));
      if (name === '_dmarc.example.com') return Promise.resolve([['v=DMARC1; p=reject']]);
      return Promise.resolve([['hello']]);
    });
    const resolver = fakeResolver({ resolveTxt });

    const result = await resolveDns('www.example.com', resolver);

    expect(result.dmarc?.policy).toBe('reject');
    expect(result.dmarcFoundAt).toBe('example.com');
  });

  it('does not report DMARC missing when it exists only at the organizational domain', async () => {
    const resolveTxt = vi.fn((name: string) => {
      if (name === '_dmarc.www.example.com') return Promise.reject(codeError('ENODATA'));
      if (name === '_dmarc.example.com') return Promise.resolve([['v=DMARC1; p=none']]);
      return Promise.reject(codeError('ENODATA'));
    });
    const resolver = fakeResolver({ resolveTxt });

    const result = await resolveDns('www.example.com', resolver);

    expect(result.dmarc).not.toBeNull();
    expect(result.dmarcTxt.ok).toBe(true);
  });

  it('reports DMARC absent when no ancestor has a record', async () => {
    const resolver = fakeResolver({
      resolveTxt: vi.fn(() => Promise.reject(codeError('ENODATA'))),
    });

    const result = await resolveDns('www.example.com', resolver);

    expect(result.dmarc).toBeNull();
    expect(result.dmarcFoundAt).toBeNull();
    expect(result.dmarcTxt).toEqual({ ok: true, records: [] });
  });

  it('stops the DMARC walk on a real lookup error instead of guessing', async () => {
    const resolveTxt = vi.fn((name: string) => {
      if (name === '_dmarc.www.example.com') return Promise.reject(codeError('ETIMEOUT'));
      return Promise.resolve([['v=DMARC1; p=reject']]);
    });
    const resolver = fakeResolver({ resolveTxt });

    const result = await resolveDns('www.example.com', resolver);

    expect(result.dmarcTxt).toEqual({ ok: false, error: { code: 'TIMEOUT', message: 'ETIMEOUT' } });
    expect(result.dmarc).toBeNull();
  });

  it('walks up the tree for CAA and records where it was found', async () => {
    const resolveCaa = vi.fn((name: string) => {
      if (name === 'www.example.com') return Promise.reject(codeError('ENODATA'));
      if (name === 'example.com')
        return Promise.resolve([{ critical: 0, issue: 'letsencrypt.org' }]);
      return Promise.reject(codeError('ENODATA'));
    });
    const resolver = fakeResolver({ resolveCaa });

    const result = await resolveDns('www.example.com', resolver);

    expect(result.caa).toEqual({
      ok: true,
      records: [{ critical: false, tag: 'issue', value: 'letsencrypt.org' }],
    });
    expect(result.caaFoundAt).toBe('example.com');
  });

  it('reports CAA absent when no ancestor has a record set', async () => {
    const resolver = fakeResolver({
      resolveCaa: vi.fn(() => Promise.reject(codeError('ENODATA'))),
    });

    const result = await resolveDns('a.b.example.com', resolver);

    expect(result.caa).toEqual({ ok: true, records: [] });
    expect(result.caaFoundAt).toBeNull();
  });
});
