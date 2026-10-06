import { resolveTarget, type ResolveResult } from '@sentinel/core';
import { connectTls, type TlsConnectOptions } from './connect.js';
import type { TlsOutcome } from './types.js';

export interface TlsScanOptions {
  port?: number;
  allowPrivate?: boolean;
  timeoutMs?: number;
  /** Injectable for tests. Defaults to net-guard's resolveTarget. */
  resolve?: (host: string, options: { allowPrivate: boolean }) => Promise<ResolveResult>;
  /** Injectable for tests. Defaults to a real TLS connection. */
  connect?: (options: TlsConnectOptions) => Promise<TlsOutcome>;
}

export async function scanTls(host: string, options: TlsScanOptions = {}): Promise<TlsOutcome> {
  const {
    port = 443,
    allowPrivate = false,
    timeoutMs = 5000,
    resolve = resolveTarget,
    connect = connectTls,
  } = options;

  const target = await resolve(host, { allowPrivate });
  const ip = target.allowed ? target.ips[0] : undefined;
  if (!target.allowed || ip === undefined) {
    const message = target.allowed ? 'no usable IP address' : target.reason;
    return { ok: false, error: { code: 'BLOCKED_TARGET', message } };
  }

  return connect({ hostname: host, ip, port, timeoutMs });
}
