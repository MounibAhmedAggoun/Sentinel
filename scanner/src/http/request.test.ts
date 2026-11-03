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
});
