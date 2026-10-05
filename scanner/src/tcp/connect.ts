import net from 'node:net';
import type { PortResult } from './types.js';

/** Tries one TCP connection to a validated IP, then closes it. No data is sent or read. */
export function checkPort(ip: string, port: number, timeoutMs: number): Promise<PortResult> {
  return new Promise((resolve) => {
    const started = performance.now();
    const socket = new net.Socket();
    let settled = false;

    const finish = (state: PortResult['state'], error?: string): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      const timingMs = Math.round(performance.now() - started);
      resolve(error === undefined ? { port, state, timingMs } : { port, state, timingMs, error });
    };

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish('open'));
    socket.once('timeout', () => finish('timeout'));
    socket.once('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'ECONNREFUSED') finish('closed');
      else finish('error', err.code ?? err.message);
    });

    socket.connect({ host: ip, port });
  });
}
