import { resolveTarget, type ResolveResult } from '@sentinel/core';
import { connectTls, type TlsConnectOptions } from './connect.js';
import type { TlsOutcome } from './types.js';

export interface TlsScanOptions {
  port?: number;
  allowPrivate?: boolean;
  timeoutMs?: number;
  /** Also probe for legacy (TLSv1/1.1) and TLSv1.3 support. Off by default. */
  probeLegacy?: boolean;
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
  if (!target.allowed || target.ips.length === 0) {
    const message = target.allowed ? 'no usable IP address' : target.reason;
    return { ok: false, error: { code: 'BLOCKED_TARGET', message } };
  }

  // Try each validated address in order. Only a refused connection or a
  // timeout moves on to the next one. Any other outcome is returned as is.
  let outcome: TlsOutcome = {
    ok: false,
    error: { code: 'BLOCKED_TARGET', message: 'no usable IP address' },
  };
  for (const ip of target.ips) {
    outcome = await connect({
      hostname: host,
      ip,
      port,
      timeoutMs,
      ...(options.probeLegacy !== undefined ? { probeLegacy: options.probeLegacy } : {}),
    });
    if (outcome.ok) return outcome;
    if (outcome.error.code !== 'CONNECTION_FAILED' && outcome.error.code !== 'TIMEOUT') {
      return outcome;
    }
  }
  return outcome;
}
