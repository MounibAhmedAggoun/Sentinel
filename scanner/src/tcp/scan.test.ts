import { describe, expect, it, vi } from 'vitest';
import type { ResolveResult } from '@sentinel/core';
import { scanPorts } from './scan.js';
import { DEFAULT_PORTS } from './ports.js';
import type { PortResult } from './types.js';

const PUBLIC_IP = '93.184.216.34';

const allow = (host: string): Promise<ResolveResult> =>
  Promise.resolve({ allowed: true, hostname: host, ips: [PUBLIC_IP] });

const open = (port: number): Promise<PortResult> =>
  Promise.resolve({ port, state: 'open', timingMs: 1 });

describe('scanPorts', () => {
  it('checks the default ports in order, connecting to the validated IP', async () => {
    const check = vi.fn((_ip: string, port: number) => open(port));

    const outcome = await scanPorts('example.com', { resolve: allow, check });

    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.result.ip).toBe(PUBLIC_IP);
    expect(outcome.result.ports.map((p) => p.port)).toEqual([...DEFAULT_PORTS]);
    expect(check.mock.calls.every((call) => call[0] === PUBLIC_IP)).toBe(true);
  });

  it('checks only the requested ports', async () => {
    const check = vi.fn((_ip: string, port: number) => open(port));

    const outcome = await scanPorts('example.com', { ports: [80, 443], resolve: allow, check });

    expect(outcome.ok && outcome.result.ports.map((p) => p.port)).toEqual([80, 443]);
    expect(check).toHaveBeenCalledTimes(2);
  });

  it('never runs more checks at once than the concurrency limit', async () => {
    let active = 0;
    let peak = 0;
    const check = async (_ip: string, port: number): Promise<PortResult> => {
      active++;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 10));
      active--;
      return { port, state: 'open', timingMs: 10 };
    };

    await scanPorts('example.com', { resolve: allow, check, concurrency: 3 });

    expect(peak).toBeLessThanOrEqual(3);
    expect(peak).toBeGreaterThan(1);
  });

  it('does not connect anywhere when net-guard blocks the target', async () => {
    const resolve = (): Promise<ResolveResult> =>
      Promise.resolve({ allowed: false, reason: 'blocked address range: private' });
    const check = vi.fn();

    const outcome = await scanPorts('internal.test', { resolve, check });

    expect(outcome).toEqual({
      ok: false,
      error: { code: 'BLOCKED_TARGET', message: 'blocked address range: private' },
    });
    expect(check).not.toHaveBeenCalled();
  });

  it('keeps mixed states in the right slots', async () => {
    const states: Record<number, PortResult['state']> = {
      80: 'open',
      443: 'closed',
      22: 'timeout',
    };
    const check = (_ip: string, port: number): Promise<PortResult> =>
      Promise.resolve({ port, state: states[port] ?? 'error', timingMs: 1 });

    const outcome = await scanPorts('example.com', { ports: [22, 80, 443], resolve: allow, check });

    expect(outcome.ok && outcome.result.ports.map((p) => p.state)).toEqual([
      'timeout',
      'open',
      'closed',
    ]);
  });
});
