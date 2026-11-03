import { describe, expect, it } from 'vitest';
import { resolveTarget } from './resolve-target.js';

/**
 * Real-DNS tests: no mocks. These go through the system resolver, so they only
 * use names whose answer does not depend on the internet.
 */

describe('resolveTarget with the real resolver', () => {
  it('blocks localhost, which really resolves to loopback', async () => {
    const result = await resolveTarget('localhost');

    expect(result.allowed).toBe(false);
    if (!result.allowed) expect(result.reason).toContain('blocked address range');
  });

  it('allows localhost only with allowPrivate', async () => {
    const result = await resolveTarget('localhost', { allowPrivate: true });

    expect(result.allowed).toBe(true);
    if (result.allowed) {
      expect(result.ips.length).toBeGreaterThan(0);
      for (const ip of result.ips) expect(['127.0.0.1', '::1']).toContain(ip);
    }
  });

  it('blocks localhost with a trailing dot', async () => {
    expect((await resolveTarget('localhost.')).allowed).toBe(false);
  });

  it('blocks mixed-case localhost', async () => {
    expect((await resolveTarget('LocalHost')).allowed).toBe(false);
  });

  it.each(['2130706433', '0x7f000001', '0177.0.0.1', '127.1', '0'])(
    'blocks the numeric loopback form %s even though the system resolver may accept it',
    async (form) => {
      expect((await resolveTarget(form)).allowed).toBe(false);
    },
  );

  it('blocks a name that does not exist (.invalid is reserved and never resolves)', async () => {
    const result = await resolveTarget('sentinel-test.invalid');

    expect(result).toEqual({ allowed: false, reason: 'hostname did not resolve' });
  });

  it('never allows link-local metadata, even with allowPrivate', async () => {
    const result = await resolveTarget('169.254.169.254', { allowPrivate: true });

    expect(result.allowed).toBe(false);
  });
});
