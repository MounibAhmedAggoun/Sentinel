import { describe, expect, it } from 'vitest';
import { checkIp } from './net-guard.js';

describe('checkIp', () => {
  it.each([
    ['127.0.0.1', 'loopback'],
    ['10.0.0.5', 'private'],
    ['192.168.1.1', 'private'],
    ['169.254.169.254', 'cloud metadata (link-local)'],
    ['0.0.0.0', 'unspecified'],
    ['::1', 'IPv6 loopback'],
    ['fe80::1', 'IPv6 link-local'],
    ['::ffff:10.0.0.1', 'IPv4-mapped private'],
    ['::ffff:127.0.0.1', 'IPv4-mapped loopback'],
    ['2130706433', 'decimal form of 127.0.0.1'],
    ['0x7f000001', 'hex form of 127.0.0.1'],
    ['not-an-ip', 'garbage'],
  ])('blocks %s (%s)', (input) => {
    expect(checkIp(input).allowed).toBe(false);
  });

  it.each(['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111'])('allows public IP %s', (input) => {
    expect(checkIp(input).allowed).toBe(true);
  });
});

describe('checkIp with allowPrivate', () => {
  it.each(['127.0.0.1', '10.0.0.5', '192.168.1.1', '::1'])('allows %s', (input) => {
    expect(checkIp(input, { allowPrivate: true }).allowed).toBe(true);
  });

  it.each(['169.254.169.254', 'fe80::1', '0.0.0.0'])('still blocks %s', (input) => {
    expect(checkIp(input, { allowPrivate: true }).allowed).toBe(false);
  });
});
