import { describe, expect, it } from 'vitest';
import { checkIp } from './net-guard.js';

/**
 * SSRF corpus: a table of known bypass attempts and the result net-guard must
 * give. Add a row whenever a new trick is found. Every row runs against the
 * real checkIp, with no mocks.
 */

const NUMERIC_FORMS = [
  '2130706433', // 127.0.0.1 as one integer
  '0x7f000001', // hex
  '0177.0.0.1', // octal octet
  '127.1', // short form
  '0', // 0.0.0.0
  '0.0.0.0',
  '127.0.0.1',
  '127.255.255.255',
];

const IPV6_FORMS = [
  '::1',
  '::',
  '::ffff:127.0.0.1', // IPv4-mapped loopback
  '::ffff:7f00:1', // same, hex form
  '::ffff:169.254.169.254', // IPv4-mapped cloud metadata
  '::ffff:a9fe:a9fe', // same, hex form
  '::ffff:0:127.0.0.1', // IPv4-translated
  'fe80::1', // link-local
  'fe80::1%eth0', // link-local with zone id
  'fc00::1', // unique local
  'fd12:3456:789a::1', // unique local
  'ff02::1', // multicast
  '64:ff9b::7f00:1', // NAT64 wrapper of 127.0.0.1
  '2002:7f00:1::', // 6to4 wrapper of 127.0.0.1
  '[::1]', // brackets are not part of an IP
];

const SPECIAL_IPV4_RANGES = [
  '10.0.0.1',
  '172.16.0.1',
  '172.31.255.255',
  '192.168.1.1',
  '100.64.0.1', // CGNAT
  '100.127.255.255', // CGNAT upper edge
  '169.254.169.254', // cloud metadata
  '169.254.0.1', // link-local
  '192.0.0.1', // IETF protocol assignments
  '192.0.2.1', // TEST-NET-1
  '198.18.0.1', // benchmarking
  '198.19.255.255', // benchmarking upper edge
  '198.51.100.1', // TEST-NET-2
  '203.0.113.1', // TEST-NET-3
  '192.88.99.1', // 6to4 relay anycast
  '224.0.0.1', // multicast
  '239.255.255.255', // multicast upper edge
  '240.0.0.1', // reserved
  '255.255.255.255', // broadcast
];

const NOT_IP_ADDRESSES = [
  'localhost',
  'localhost.',
  'example.com',
  '',
  ' 127.0.0.1',
  '127.0.0.1 ',
  '127.0.0.1\n',
  '1.1.1.1/24',
];

const PUBLIC_ADDRESSES = [
  '8.8.8.8',
  '1.1.1.1',
  '93.184.216.34',
  '2606:4700:4700::1111',
  '2001:4860:4860::8888',
];

describe('SSRF corpus: always blocked', () => {
  const groups: [string, string[]][] = [
    ['numeric forms', NUMERIC_FORMS],
    ['IPv6 forms', IPV6_FORMS],
    ['special IPv4 ranges', SPECIAL_IPV4_RANGES],
    ['not IP addresses', NOT_IP_ADDRESSES],
  ];

  for (const [name, payloads] of groups) {
    describe(name, () => {
      it.each(payloads)('blocks %j', (payload) => {
        const result = checkIp(payload);

        expect(result.allowed).toBe(false);
        if (!result.allowed) expect(result.reason).not.toBe('');
      });
    });
  }
});

describe('SSRF corpus: public addresses stay allowed', () => {
  it.each(PUBLIC_ADDRESSES)('allows %s', (address) => {
    expect(checkIp(address).allowed).toBe(true);
  });
});

describe('SSRF corpus: with allowPrivate', () => {
  it.each(['127.0.0.1', '10.0.0.1', '192.168.1.1', '172.16.0.1', '::1', 'fc00::1'])(
    'allows local address %s',
    (address) => {
      expect(checkIp(address, { allowPrivate: true }).allowed).toBe(true);
    },
  );

  it.each([
    '169.254.169.254',
    '169.254.0.1',
    'fe80::1',
    '::ffff:169.254.169.254',
    '0.0.0.0',
    '224.0.0.1',
    '100.64.0.1',
    '255.255.255.255',
  ])('still blocks %s', (address) => {
    expect(checkIp(address, { allowPrivate: true }).allowed).toBe(false);
  });
});
