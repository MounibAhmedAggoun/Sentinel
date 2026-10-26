import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { probeLegacyProtocols } from './legacy-probe.js';

let dir: string;
let server: tls.Server;
let port: number;

beforeAll(async () => {
  dir = mkdtempSync(path.join(tmpdir(), 'sentinel-legacy-tls-'));
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

  // A modern server: minVersion TLSv1.2, so it should refuse TLSv1/1.1
  // handshakes and accept a TLSv1.3-only handshake.
  server = tls.createServer(
    {
      key: readFileSync(path.join(dir, 'key.pem')),
      cert: readFileSync(path.join(dir, 'cert.pem')),
      minVersion: 'TLSv1.2',
    },
    (socket) => {
      socket.on('error', () => {});
      socket.end();
    },
  );
  server.on('tlsClientError', () => {});
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = (server.address() as AddressInfo).port;
});

afterAll(async () => {
  server.close();
  rmSync(dir, { recursive: true, force: true });
});

describe('probeLegacyProtocols against a modern-only local server', () => {
  it('reports no legacy versions accepted', async () => {
    const result = await probeLegacyProtocols('127.0.0.1', 'localhost', port);

    expect(result.acceptedLegacyVersions).toEqual([]);
  }, 15_000);

  it('reports TLS 1.3 as supported', async () => {
    const result = await probeLegacyProtocols('127.0.0.1', 'localhost', port);

    expect(result.missingTls13).toBe(false);
  }, 15_000);
});

describe('probeLegacyProtocols against a legacy-only local server', () => {
  let legacyDir: string;
  let legacyServer: tls.Server;
  let legacyPort: number;

  beforeAll(async () => {
    legacyDir = mkdtempSync(path.join(tmpdir(), 'sentinel-legacy-tls-2-'));
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-keyout',
        path.join(legacyDir, 'key.pem'),
        '-out',
        path.join(legacyDir, 'cert.pem'),
        '-days',
        '2',
        '-subj',
        '/CN=localhost',
        '-addext',
        'subjectAltName=DNS:localhost,IP:127.0.0.1',
      ],
      { stdio: 'ignore' },
    );

    // A deliberately old server: pinned to TLSv1.1 only, with the relaxed
    // security level needed for OpenSSL to even allow it. This is NOT
    // something to copy elsewhere in the codebase - this one test file is
    // where we intentionally need to speak a legacy protocol.
    legacyServer = tls.createServer(
      {
        key: readFileSync(path.join(legacyDir, 'key.pem')),
        cert: readFileSync(path.join(legacyDir, 'cert.pem')),
        minVersion: 'TLSv1.1',
        maxVersion: 'TLSv1.1',
        ciphers: 'DEFAULT@SECLEVEL=0',
      },
      (socket) => {
        socket.on('error', () => {});
        socket.end();
      },
    );
    legacyServer.on('tlsClientError', () => {});
    await new Promise<void>((resolve) => legacyServer.listen(0, '127.0.0.1', resolve));
    legacyPort = (legacyServer.address() as AddressInfo).port;
  });

  afterAll(async () => {
    legacyServer.close();
    rmSync(legacyDir, { recursive: true, force: true });
  });

  it('detects that TLSv1.1 is accepted', async () => {
    const result = await probeLegacyProtocols('127.0.0.1', 'localhost', legacyPort);

    expect(result.acceptedLegacyVersions).toContain('TLSv1.1');
  }, 15_000);

  it('reports TLS 1.3 as not supported', async () => {
    const result = await probeLegacyProtocols('127.0.0.1', 'localhost', legacyPort);

    expect(result.missingTls13).toBe(true);
  }, 15_000);
});
