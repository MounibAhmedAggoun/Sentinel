import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('node:dns/promises', () => ({ lookup: vi.fn() }));

import { lookup } from 'node:dns/promises';
import { resolveTarget } from './resolve-target.js';

const mockLookup = vi.mocked(lookup) as unknown as ReturnType<typeof vi.fn>;

describe('resolveTarget', () => {
  beforeEach(() => {
    mockLookup.mockReset();
  });

  it('blocks a private IP given directly', async () => {
    const result = await resolveTarget('10.0.0.5');
    expect(result.allowed).toBe(false);
    expect(mockLookup).not.toHaveBeenCalled();
  });

  it('allows a public IP given directly', async () => {
    const result = await resolveTarget('8.8.8.8');
    expect(result).toEqual({ allowed: true, hostname: '8.8.8.8', ips: ['8.8.8.8'] });
  });

  it('allows a hostname that resolves to a public IP', async () => {
    mockLookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
    const result = await resolveTarget('example.com');
    expect(result).toEqual({ allowed: true, hostname: 'example.com', ips: ['93.184.216.34'] });
  });

  it('blocks a hostname that resolves to a private IP', async () => {
    mockLookup.mockResolvedValue([{ address: '10.0.0.5', family: 4 }]);
    const result = await resolveTarget('internal.example.com');
    expect(result.allowed).toBe(false);
  });

  it('blocks a hostname that resolves to cloud metadata', async () => {
    mockLookup.mockResolvedValue([{ address: '169.254.169.254', family: 4 }]);
    const result = await resolveTarget('metadata.example.com');
    expect(result.allowed).toBe(false);
  });

  it('blocks if any one resolved IP is private', async () => {
    mockLookup.mockResolvedValue([
      { address: '93.184.216.34', family: 4 },
      { address: '127.0.0.1', family: 4 },
    ]);
    const result = await resolveTarget('mixed.example.com');
    expect(result.allowed).toBe(false);
  });

  it('blocks a hostname that fails to resolve', async () => {
    mockLookup.mockRejectedValue(new Error('ENOTFOUND'));
    const result = await resolveTarget('nope.invalid');
    expect(result.allowed).toBe(false);
  });
});
