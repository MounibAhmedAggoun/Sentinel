import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { fetchHttp } from './fetch.js';

let server: http.Server;
let base: string;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    switch (req.url) {
      case '/ok':
        res.writeHead(200, {
          server: 'mock',
          'set-cookie': ['sid=abc; Secure; HttpOnly; SameSite=Lax'],
        });
        res.end('hello');
        break;
      case '/a':
        res.writeHead(302, { location: '/b' });
        res.end();
        break;
      case '/b':
        res.writeHead(301, { location: '/ok' });
        res.end();
        break;
      case '/loop':
        res.writeHead(302, { location: '/loop' });
        res.end();
        break;
      case '/to-metadata':
        res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data/' });
        res.end();
        break;
      case '/slow':
        setTimeout(() => {
          if (!res.destroyed) {
            res.writeHead(200);
            res.end();
          }
        }, 2000);
        break;
      default:
        res.writeHead(404);
        res.end();
    }
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

// The mock server is on loopback, so these tests need allowPrivate.
const local = { allowPrivate: true };

describe('fetchHttp against a local mock server', () => {
  it('records status, headers, cookies and timing', async () => {
    const result = await fetchHttp(`${base}/ok`, local);

    expect(result.error).toBeNull();
    expect(result.hops).toHaveLength(1);
    const hop = result.hops[0];
    expect(hop?.status).toBe(200);
    expect(hop?.headers['server']).toBe('mock');
    expect(hop?.remoteIp).toBe('127.0.0.1');
    expect(hop?.timingMs).toBeGreaterThanOrEqual(0);
    expect(hop?.cookies).toEqual([{ name: 'sid', secure: true, httpOnly: true, sameSite: 'lax' }]);
  });

  it('follows a redirect chain to the final URL', async () => {
    const result = await fetchHttp(`${base}/a`, local);

    expect(result.error).toBeNull();
    expect(result.hops.map((h) => h.status)).toEqual([302, 301, 200]);
    expect(result.finalUrl).toBe(`${base}/ok`);
  });

  it('stops a redirect loop', async () => {
    const result = await fetchHttp(`${base}/loop`, { ...local, maxRedirects: 3 });

    expect(result.error?.code).toBe('TOO_MANY_REDIRECTS');
    expect(result.hops).toHaveLength(4);
  });

  it('times out on a slow response', async () => {
    const started = Date.now();
    const result = await fetchHttp(`${base}/slow`, { ...local, timeoutMs: 300 });

    expect(result.error?.code).toBe('TIMEOUT');
    expect(Date.now() - started).toBeLessThan(1500);
  });

  it('blocks a redirect to cloud metadata even with allowPrivate', async () => {
    const result = await fetchHttp(`${base}/to-metadata`, local);

    expect(result.error?.code).toBe('BLOCKED_TARGET');
    expect(result.hops).toHaveLength(1);
  });

  it('refuses the loopback server when allowPrivate is off', async () => {
    const result = await fetchHttp(`${base}/ok`);

    expect(result.error?.code).toBe('BLOCKED_TARGET');
    expect(result.hops).toHaveLength(0);
  });

  it('reports a closed port as a connection failure', async () => {
    const result = await fetchHttp('http://127.0.0.1:1/', { ...local, timeoutMs: 2000 });

    expect(result.error?.code).toBe('CONNECTION_FAILED');
  });
});
