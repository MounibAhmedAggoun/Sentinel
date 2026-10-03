import http from 'node:http';
import https from 'node:https';
import type { LookupFunction } from 'node:net';
import type { HttpErrorCode } from './types.js';

export class HttpRequestError extends Error {
  readonly code: HttpErrorCode;

  constructor(code: HttpErrorCode, message: string) {
    super(message);
    this.name = 'HttpRequestError';
    this.code = code;
  }
}

export interface RawResponse {
  status: number;
  headers: Record<string, string | string[]>;
  remoteIp: string;
  timingMs: number;
}

const TLS_ERROR = /^(ERR_TLS|ERR_SSL|CERT_|UNABLE_TO_|SELF_SIGNED|DEPTH_ZERO|HOSTNAME_MISMATCH)/;

function toHttpError(err: unknown): HttpRequestError {
  if (err instanceof HttpRequestError) return err;
  const code = (err as { code?: unknown } | null)?.code;
  const message = err instanceof Error ? err.message : 'unknown error';
  if (typeof code === 'string') {
    if (TLS_ERROR.test(code)) return new HttpRequestError('TLS_ERROR', message);
    if (code === 'ETIMEDOUT') return new HttpRequestError('TIMEOUT', message);
    if (code.startsWith('E')) return new HttpRequestError('CONNECTION_FAILED', message);
  }
  return new HttpRequestError('UNKNOWN', message);
}

/**
 * Sends one GET request to a pre-validated IP. The hostname is only used for the
 * Host header and TLS name check, never for a new DNS lookup (prevents DNS rebinding).
 * Only the headers are read. The body is never downloaded.
 */
export function requestOnce(
  url: URL,
  ip: string,
  options: { timeoutMs: number },
): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const started = performance.now();
    const family = ip.includes(':') ? 6 : 4;

    const pinnedLookup: LookupFunction = (_hostname, lookupOptions, callback) => {
      if (lookupOptions.all) callback(null, [{ address: ip, family }]);
      else callback(null, ip, family);
    };

    const isHttps = url.protocol === 'https:';
    const transport = isHttps ? https : http;

    const req = transport.request(
      {
        host: url.hostname.replace(/^\[|\]$/g, ''),
        port: url.port === '' ? (isHttps ? 443 : 80) : Number(url.port),
        path: url.pathname + url.search,
        method: 'GET',
        lookup: pinnedLookup,
        agent: false,
        headers: {
          'user-agent': 'Sentinel/0.0.0 (authorized security scanner)',
          accept: '*/*',
          connection: 'close',
        },
      },
      (res) => {
        clearTimeout(timer);
        const headers: Record<string, string | string[]> = {};
        for (const [name, value] of Object.entries(res.headers)) {
          if (value !== undefined) headers[name] = value;
        }
        const result: RawResponse = {
          status: res.statusCode ?? 0,
          headers,
          remoteIp: ip,
          timingMs: Math.round(performance.now() - started),
        };
        res.destroy();
        resolve(result);
      },
    );

    const timer = setTimeout(() => {
      req.destroy(new HttpRequestError('TIMEOUT', `no response within ${options.timeoutMs}ms`));
    }, options.timeoutMs);

    req.on('error', (err) => {
      clearTimeout(timer);
      reject(toHttpError(err));
    });

    req.end();
  });
}
