import { resolveTarget, type ResolveResult } from '@sentinel/core';
import { parseCookies } from './cookies.js';
import { HttpRequestError, requestOnce, type RawResponse } from './request.js';
import type { HttpError, HttpHop, HttpResult } from './types.js';

export interface FetchOptions {
  allowPrivate?: boolean;
  timeoutMs?: number;
  maxRedirects?: number;
  /** Injectable for tests. Defaults to net-guard's resolveTarget. */
  resolve?: (host: string, options: { allowPrivate: boolean }) => Promise<ResolveResult>;
  /** Injectable for tests. Defaults to a real HTTP request. */
  send?: (url: URL, ip: string, options: { timeoutMs: number }) => Promise<RawResponse>;
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function fail(result: HttpResult, error: HttpError): HttpResult {
  return { ...result, error };
}

export async function fetchHttp(startUrl: string, options: FetchOptions = {}): Promise<HttpResult> {
  const {
    allowPrivate = false,
    timeoutMs = 10_000,
    maxRedirects = 5,
    resolve = resolveTarget,
    send = requestOnce,
  } = options;

  const result: HttpResult = { startUrl, finalUrl: null, hops: [], error: null };

  let current: URL;
  try {
    current = new URL(startUrl);
  } catch {
    return fail(result, { code: 'INVALID_URL', message: 'not a valid URL' });
  }

  for (let redirects = 0; ; redirects++) {
    if (current.protocol !== 'http:' && current.protocol !== 'https:') {
      return fail(result, {
        code: 'INVALID_URL',
        message: `unsupported protocol: ${current.protocol}`,
      });
    }

    // net-guard runs on EVERY hop, including redirect targets.
    const host = current.hostname.replace(/^\[|\]$/g, '');
    const target = await resolve(host, { allowPrivate });
    if (!target.allowed) {
      return fail(result, { code: 'BLOCKED_TARGET', message: target.reason });
    }
    const ip = target.ips[0];
    if (ip === undefined) {
      return fail(result, { code: 'BLOCKED_TARGET', message: 'no usable IP address' });
    }

    let response: RawResponse;
    try {
      response = await send(current, ip, { timeoutMs });
    } catch (err) {
      const e = err instanceof HttpRequestError ? err : null;
      return fail(result, {
        code: e?.code ?? 'UNKNOWN',
        message: err instanceof Error ? err.message : 'unknown error',
      });
    }

    const setCookie = response.headers['set-cookie'];
    const hop: HttpHop = {
      url: current.toString(),
      status: response.status,
      headers: response.headers,
      cookies: parseCookies(Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : []),
      remoteIp: response.remoteIp,
      timingMs: response.timingMs,
    };
    result.hops.push(hop);
    result.finalUrl = hop.url;

    const location = response.headers['location'];
    if (!REDIRECT_STATUSES.has(response.status) || typeof location !== 'string') {
      return result;
    }

    if (redirects >= maxRedirects) {
      return fail(result, {
        code: 'TOO_MANY_REDIRECTS',
        message: `more than ${maxRedirects} redirects`,
      });
    }

    try {
      current = new URL(location, current);
    } catch {
      return fail(result, { code: 'INVALID_URL', message: 'redirect to an invalid URL' });
    }
  }
}
