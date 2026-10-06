import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { connectTls } from './connect.js';
import { scanTls } from './scan.js';

let dir: string;
let tlsServer: tls.Server;
let silentServer: net.Server;
let tlsPort: number;
let silentPort: number;
let closedPort: number;

beforeAll(async () => {
  // Make a throwaway self-signed certificate for localhost. Needs openssl.
  dir = mkdtempSync(path.join(tmpdir(), 'sentinel-tls-'));
  execFileSync(
    'openssl',
    [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      path.join(dir, 'key.pem'),
      '-out',
      path.join(dir, 'cert.pem'),
      '-days',
      '2',
      '-subj',
      '/CN=localhost',
      '-addext',
      'subjectAltName=DNS:localhost,IP:127.0.0.1',
    ],
    { stdio: 'ignore' },
  );

  tlsServer = tls.createServer(
    {
      key: readFileSync(path.join(dir, 'key.pem')),
      cert: readFileSync(path.join(dir, 'cert.pem')),
    },
    (socket) => {
      socket.on('error', () => {});
      socket.end();
    },
  );
  tlsServer.on('tlsClientError', () => {});
  await new Promise<void>((resolve) => tlsServer.listen(0, '127.0.0.1', resolve));
  tlsPort = (tlsServer.address() as AddressInfo).port;

  // Accepts connections but never answers, to test the timeout.
  silentServer = net.createServer((socket) => socket.on('error', () => {}));
  await new Promise<void>((resolve) => silentServer.listen(0, '127.0.0.1', resolve));
  silentPort = (silentServer.address() as AddressInfo).port;

  // A port with nothing listening.
  const temp = net.createServer();
  await new Promise<void>((resolve) => temp.listen(0, '127.0.0.1', resolve));
  closedPort = (temp.address() as AddressInfo).port;
  await new Promise<void>((resolve) => temp.close(() => resolve()));
});

afterAll(async () => {
  silentServer.close();
  tlsServer.close();
  rmSync(dir, { recursive: true, force: true });
});

describe('connectTls against a local TLS server', () => {
  it('reads certificate details, protocol and cipher', async () => {
    const outcome = await connectTls({ hostname: 'localhost', ip: '127.0.0.1', port: tlsPort });

    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.result.protocol).toMatch(/^TLSv1\.[23]$/);
    expect(outcome.result.cipher).toBeTruthy();
    expect(outcome.result.certificate.subject.commonName).toBe('localhost');
    expect(outcome.result.certificate.san).toEqual(['localhost', '127.0.0.1']);
    expect(outcome.result.certificate.fingerprint256).toBeTruthy();
  });

  it('still reads a self-signed certificate and flags it', async () => {
    const outcome = await connectTls({ hostname: 'localhost', ip: '127.0.0.1', port: tlsPort });

    expect(outcome.ok && outcome.result.analysis).toMatchObject({
      selfSigned: true,
      expired: false,
      hostnameMatches: true,
    });
    expect(outcome.ok && outcome.result.analysis.daysUntilExpiry).toBeGreaterThanOrEqual(1);
  });

  it('flags a hostname mismatch', async () => {
    const outcome = await connectTls({
      hostname: 'other.example.com',
      ip: '127.0.0.1',
      port: tlsPort,
    });

    expect(outcome.ok && outcome.result.analysis.hostnameMatches).toBe(false);
  });

  it('times out when the server never completes the handshake', async () => {
    const outcome = await connectTls({
      hostname: 'localhost',
      ip: '127.0.0.1',
      port: silentPort,
      timeoutMs: 300,
    });

    expect(outcome).toMatchObject({ ok: false, error: { code: 'TIMEOUT' } });
  });

  it('reports a closed port as a connection failure', async () => {
    const outcome = await connectTls({
      hostname: 'localhost',
      ip: '127.0.0.1',
      port: closedPort,
      timeoutMs: 2000,
    });

    expect(outcome).toMatchObject({ ok: false, error: { code: 'CONNECTION_FAILED' } });
  });
});

describe('scanTls against a local TLS server', () => {
  it('scans the server when allowPrivate is on', async () => {
    const outcome = await scanTls('127.0.0.1', { port: tlsPort, allowPrivate: true });

    expect(outcome.ok).toBe(true);
  });

  it('refuses loopback when allowPrivate is off', async () => {
    const outcome = await scanTls('127.0.0.1', { port: tlsPort });

    expect(outcome).toMatchObject({ ok: false, error: { code: 'BLOCKED_TARGET' } });
  });
});
