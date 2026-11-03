import { readFileSync } from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { HttpRequestError, requestOnce } from './request.js';

describe('requestOnce', () => {
  it('maps a synchronous request-building error to INVALID_URL', async () => {
    // A real URL object encodes illegal characters, so use a URL-like object
    // whose path contains a raw space, which Node rejects while building the request.
    const badUrl = {
      protocol: 'http:',
      hostname: 'example.com',
      port: '',
      pathname: '/bad path',
      search: '',
    } as unknown as URL;

    const outcome = await requestOnce(badUrl, '127.0.0.1', { timeoutMs: 1000 }).catch(
      (err: unknown) => err,
    );

    expect(outcome).toBeInstanceOf(HttpRequestError);
    expect(outcome).toMatchObject({ code: 'INVALID_URL' });
  });

  it('sends a User-Agent that carries the scanner package version', async () => {
    let userAgent: string | undefined;
    const server = http.createServer((req, res) => {
      userAgent = req.headers['user-agent'];
      res.end();
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

    try {
      const { port } = server.address() as AddressInfo;
      await requestOnce(new URL(`http://127.0.0.1:${port}/`), '127.0.0.1', { timeoutMs: 2000 });
    } finally {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }

    const packageJsonPath = fileURLToPath(new URL('../../package.json', import.meta.url));
    const pkg = JSON.parse(readFileSync(packageJsonPath, 'utf8')) as { version: string };

    expect(userAgent).toBe(`Sentinel/${pkg.version} (authorized security scanner)`);
  });
});
