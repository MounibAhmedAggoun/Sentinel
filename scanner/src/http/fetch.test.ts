import { describe, expect, it, vi } from 'vitest';
import type { ResolveResult } from '@sentinel/core';
import { fetchHttp } from './fetch.js';
import { HttpRequestError, type RawResponse } from './request.js';

const PUBLIC_IP = '93.184.216.34';

const allow = (host: string): Promise<ResolveResult> =>
  Promise.resolve({ allowed: true, hostname: host, ips: [PUBLIC_IP] });

function res(status: number, headers: Record<string, string | string[]> = {}): RawResponse {
  return { status, headers, remoteIp: PUBLIC_IP, timingMs: 5 };
}

describe('fetchHttp', () => {
  it('returns a single hop for a plain 200', async () => {
    const send = vi.fn().mockResolvedValue(res(200, { server: 'test' }));

    const result = await fetchHttp('https://example.com/', { resolve: allow, send });

    expect(result.error).toBeNull();
    expect(result.finalUrl).toBe('https://example.com/');
    expect(result.hops).toHaveLength(1);
    expect(result.hops[0]).toMatchObject({ status: 200, remoteIp: PUBLIC_IP });
  });

  it('connects to the IP that net-guard validated', async () => {
    const send = vi.fn().mockResolvedValue(res(200));

    await fetchHttp('https://example.com/', { resolve: allow, send });

    expect(send.mock.calls[0]?.[1]).toBe(PUBLIC_IP);
  });

  it('follows redirects and records every hop', async () => {
    const send = vi
      .fn()
      .mockResolvedValueOnce(res(301, { location: 'https://example.com/a' }))
      .mockResolvedValueOnce(res(302, { location: '/b' }))
      .mockResolvedValueOnce(res(200));

    const result = await fetchHttp('http://example.com/', { resolve: allow, send });

    expect(result.hops.map((h) => h.url)).toEqual([
      'http://example.com/',
      'https://example.com/a',
      'https://example.com/b',
    ]);
    expect(result.finalUrl).toBe('https://example.com/b');
    expect(result.error).toBeNull();
  });

  it('re-runs net-guard on every redirect hop and blocks internal targets', async () => {
    const resolve = vi.fn((host: string): Promise<ResolveResult> =>
      host === 'internal.test'
        ? Promise.resolve({ allowed: false, reason: 'blocked address range: private' })
        : allow(host),
    );
    const send = vi.fn().mockResolvedValue(res(302, { location: 'http://internal.test/admin' }));

    const result = await fetchHttp('https://example.com/', { resolve, send });

    expect(resolve).toHaveBeenCalledTimes(2);
    expect(send).toHaveBeenCalledTimes(1);
    expect(result.error?.code).toBe('BLOCKED_TARGET');
    expect(result.hops).toHaveLength(1);
  });

  it('stops after too many redirects', async () => {
    const send = vi.fn().mockResolvedValue(res(302, { location: '/loop' }));

    const result = await fetchHttp('https://example.com/', {
      resolve: allow,
      send,
      maxRedirects: 3,
    });

    expect(result.error?.code).toBe('TOO_MANY_REDIRECTS');
    expect(send).toHaveBeenCalledTimes(4);
  });

  it('rejects non-http protocols in a redirect', async () => {
    const send = vi.fn().mockResolvedValue(res(302, { location: 'file:///etc/passwd' }));

    const result = await fetchHttp('https://example.com/', { resolve: allow, send });

    expect(result.error?.code).toBe('INVALID_URL');
    expect(send).toHaveBeenCalledTimes(1);
  });

  it('returns INVALID_URL for garbage input', async () => {
    const result = await fetchHttp('not a url', { resolve: allow, send: vi.fn() });
    expect(result.error?.code).toBe('INVALID_URL');
  });

  it('turns request failures into structured errors and keeps earlier hops', async () => {
    const send = vi
      .fn()
      .mockResolvedValueOnce(res(301, { location: 'https://example.com/slow' }))
      .mockRejectedValueOnce(new HttpRequestError('TIMEOUT', 'no response within 10000ms'));

    const result = await fetchHttp('http://example.com/', { resolve: allow, send });

    expect(result.error).toEqual({ code: 'TIMEOUT', message: 'no response within 10000ms' });
    expect(result.hops).toHaveLength(1);
  });

  it('parses cookie flags without storing values', async () => {
    const send = vi
      .fn()
      .mockResolvedValue(res(200, { 'set-cookie': ['sid=SECRET; Secure; HttpOnly'] }));

    const result = await fetchHttp('https://example.com/', { resolve: allow, send });

    expect(result.hops[0]?.cookies).toEqual([
      { name: 'sid', secure: true, httpOnly: true, sameSite: null },
    ]);
  });
});
