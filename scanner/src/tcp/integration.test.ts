import net from 'node:net';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { checkPort } from './connect.js';
import { scanPorts } from './scan.js';

let server: net.Server;
let openPort: number;
let closedPort: number;

beforeAll(async () => {
  server = net.createServer((socket) => socket.destroy());
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  openPort = (server.address() as AddressInfo).port;

  // Grab a free port, then close it so nothing is listening there.
  const temp = net.createServer();
  await new Promise<void>((resolve) => temp.listen(0, '127.0.0.1', resolve));
  closedPort = (temp.address() as AddressInfo).port;
  await new Promise<void>((resolve) => temp.close(() => resolve()));
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe('checkPort against a local server', () => {
  it('reports an open port', async () => {
    const result = await checkPort('127.0.0.1', openPort, 2000);

    expect(result.state).toBe('open');
    expect(result.port).toBe(openPort);
    expect(result.timingMs).toBeGreaterThanOrEqual(0);
  });

  it('reports a closed port', async () => {
    const result = await checkPort('127.0.0.1', closedPort, 2000);

    expect(result.state).toBe('closed');
  });

  it('reports a timeout when nothing answers', async () => {
    // 10.255.255.1 is a non-routable address. Packets get dropped, so the connection hangs.
    const result = await checkPort('10.255.255.1', 80, 300);

    expect(['timeout', 'error']).toContain(result.state);
    expect(result.timingMs).toBeLessThan(1500);
  });
});

describe('scanPorts against a local server', () => {
  it('scans real ports when allowPrivate is on', async () => {
    const outcome = await scanPorts('127.0.0.1', {
      ports: [openPort, closedPort],
      allowPrivate: true,
      timeoutMs: 2000,
    });

    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.result.ports.map((p) => p.state)).toEqual(['open', 'closed']);
  });

  it('refuses loopback when allowPrivate is off', async () => {
    const outcome = await scanPorts('127.0.0.1', { ports: [openPort] });

    expect(outcome.ok).toBe(false);
  });
});
