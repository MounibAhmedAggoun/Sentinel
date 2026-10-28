import net from 'node:net';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { scanPorts } from '../../tcp/scan.js';
import { RULE_IDS } from '../ids.js';
import { tcpRules } from './tcp.js';

// A plain TCP listener standing in for a real database port. Our scanner
// only tests reachability (connect/disconnect), not the MySQL/Redis/etc.
// wire protocol, so a bare socket proves the same thing a real database
// would for this rule: that the port accepts a connection.
let server: net.Server;
let port: number;

beforeAll(async () => {
  server = net.createServer((socket) => socket.destroy());
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = (server.address() as AddressInfo).port;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe('tcpRules against a real local port, end to end', () => {
  it('a real open sensitive-port connection produces a real TCP-002 finding', async () => {
    const outcome = await scanPorts('127.0.0.1', {
      ports: [3306],
      allowPrivate: true,
      timeoutMs: 2000,
      // Real scanPorts logic, real socket connect - only the target port
      // number is substituted so we can run this locally without a real
      // MySQL server, and without requiring port 3306 specifically to be
      // free on the test machine.
      check: (ip, _port, timeoutMs) =>
        import('../../tcp/connect.js').then(({ checkPort }) =>
          checkPort(ip, port, timeoutMs).then((result) => ({ ...result, port: 3306 })),
        ),
    });

    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;

    const scan = {
      target: '127.0.0.1',
      dns: {} as never,
      http: {} as never,
      httpPlain: {} as never,
      tcp: outcome,
      tls: { ok: false as const, error: { code: 'TIMEOUT' as const, message: 'n/a' } },
    };

    const findings = tcpRules(scan);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe(RULE_IDS.TCP_SENSITIVE_PORT_OPEN);
    expect(findings[0]?.severity).toBe('medium');
    expect(findings[0]?.title).toContain('MySQL');
  });
});
