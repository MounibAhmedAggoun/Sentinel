import { resolveTarget, type ResolveResult } from '@sentinel/core';
import { checkPort } from './connect.js';
import { DEFAULT_PORTS } from './ports.js';
import type { PortResult, TcpResult } from './types.js';

export interface TcpScanOptions {
  ports?: readonly number[];
  allowPrivate?: boolean;
  timeoutMs?: number;
  concurrency?: number;
  /** Injectable for tests. Defaults to net-guard's resolveTarget. */
  resolve?: (host: string, options: { allowPrivate: boolean }) => Promise<ResolveResult>;
  /** Injectable for tests. Defaults to a real TCP connection. */
  check?: (ip: string, port: number, timeoutMs: number) => Promise<PortResult>;
}

export type TcpScanOutcome =
  | { ok: true; result: TcpResult }
  | { ok: false; error: { code: 'BLOCKED_TARGET'; message: string } };

export async function scanPorts(
  host: string,
  options: TcpScanOptions = {},
): Promise<TcpScanOutcome> {
  const {
    ports = DEFAULT_PORTS,
    allowPrivate = false,
    timeoutMs = 3000,
    concurrency = 5,
    resolve = resolveTarget,
    check = checkPort,
  } = options;

  const target = await resolve(host, { allowPrivate });
  const ip = target.allowed ? target.ips[0] : undefined;
  if (!target.allowed || ip === undefined) {
    const message = target.allowed ? 'no usable IP address' : target.reason;
    return { ok: false, error: { code: 'BLOCKED_TARGET', message } };
  }

  // Small worker pool: at most `concurrency` connections are in flight at once.
  const results: PortResult[] = new Array<PortResult>(ports.length);
  let next = 0;

  async function worker(): Promise<void> {
    while (next < ports.length) {
      const index = next++;
      const port = ports[index];
      if (port === undefined) continue;
      results[index] = await check(ip as string, port, timeoutMs);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, ports.length) }, () => worker());
  await Promise.all(workers);

  return { ok: true, result: { ip, ports: results } };
}
