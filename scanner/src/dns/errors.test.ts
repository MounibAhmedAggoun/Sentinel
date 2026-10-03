import { describe, expect, it } from 'vitest';
import { toDnsError } from './errors.js';

describe('toDnsError', () => {
  it.each([
    ['ENOTFOUND', 'NXDOMAIN'],
    ['ENODATA', 'NODATA'],
    ['ETIMEOUT', 'TIMEOUT'],
    ['ETIMEDOUT', 'TIMEOUT'],
    ['ESERVFAIL', 'SERVFAIL'],
    ['EREFUSED', 'REFUSED'],
  ])('maps %s to %s', (nodeCode, expected) => {
    const err = Object.assign(new Error('boom'), { code: nodeCode });
    expect(toDnsError(err).code).toBe(expected);
  });

  it('maps an unrecognized code to UNKNOWN', () => {
    const err = Object.assign(new Error('weird'), { code: 'EWEIRD' });
    expect(toDnsError(err).code).toBe('UNKNOWN');
  });

  it('handles errors with no code', () => {
    expect(toDnsError(new Error('plain')).code).toBe('UNKNOWN');
  });

  it('handles non-error values', () => {
    expect(toDnsError('oops')).toEqual({ code: 'UNKNOWN', message: 'unknown DNS error' });
    expect(toDnsError(null).code).toBe('UNKNOWN');
  });

  it('keeps the original message', () => {
    const err = Object.assign(new Error('queryA ENOTFOUND nope.invalid'), { code: 'ENOTFOUND' });
    expect(toDnsError(err).message).toBe('queryA ENOTFOUND nope.invalid');
  });
});
