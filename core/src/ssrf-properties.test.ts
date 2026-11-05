import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { checkIp } from './net-guard.js';

/**
 * Property-based tests: instead of hand-picked addresses, fast-check generates
 * many random addresses inside each range and every one must get the same verdict.
 * Every address is tried as dotted IPv4, as IPv4-mapped IPv6 (dotted), and as
 * IPv4-mapped IPv6 (hex).
 */

interface Cidr {
  name: string;
  base: string;
  prefix: number;
}

// Blocked even with allowPrivate.
const ALWAYS_BLOCKED: Cidr[] = [
  { name: 'unspecified', base: '0.0.0.0', prefix: 8 },
  { name: 'carrier-grade NAT', base: '100.64.0.0', prefix: 10 },
  { name: 'link-local (cloud metadata)', base: '169.254.0.0', prefix: 16 },
  { name: 'IETF protocol assignments', base: '192.0.0.0', prefix: 24 },
  { name: 'TEST-NET-1', base: '192.0.2.0', prefix: 24 },
  { name: 'benchmarking', base: '198.18.0.0', prefix: 15 },
  { name: 'TEST-NET-2', base: '198.51.100.0', prefix: 24 },
  { name: 'TEST-NET-3', base: '203.0.113.0', prefix: 24 },
  { name: 'multicast', base: '224.0.0.0', prefix: 4 },
  { name: 'reserved and broadcast', base: '240.0.0.0', prefix: 4 },
];

// Blocked by default, allowed only with allowPrivate.
const LOCAL_ONLY: Cidr[] = [
  { name: 'loopback', base: '127.0.0.0', prefix: 8 },
  { name: 'private 10/8', base: '10.0.0.0', prefix: 8 },
  { name: 'private 172.16/12', base: '172.16.0.0', prefix: 12 },
  { name: 'private 192.168/16', base: '192.168.0.0', prefix: 16 },
];

const toInt = (ip: string): number =>
  ip.split('.').reduce((acc, part) => acc * 256 + Number(part), 0);

const toDotted = (n: number): string =>
  [
    Math.floor(n / 16777216) % 256,
    Math.floor(n / 65536) % 256,
    Math.floor(n / 256) % 256,
    n % 256,
  ].join('.');

const toMappedDotted = (n: number): string => `::ffff:${toDotted(n)}`;

const toMappedHex = (n: number): string =>
  `::ffff:${Math.floor(n / 65536).toString(16)}:${(n % 65536).toString(16)}`;

const FORMS: [string, (n: number) => string][] = [
  ['dotted IPv4', toDotted],
  ['IPv4-mapped IPv6 (dotted)', toMappedDotted],
  ['IPv4-mapped IPv6 (hex)', toMappedHex],
];

function addressIn(cidr: Cidr): fc.Arbitrary<number> {
  const size = 2 ** (32 - cidr.prefix);
  const base = toInt(cidr.base);
  return fc.integer({ min: 0, max: size - 1 }).map((offset) => base + offset);
}

const inAny = (n: number, ranges: Cidr[]): boolean =>
  ranges.some((c) => n >= toInt(c.base) && n < toInt(c.base) + 2 ** (32 - c.prefix));

describe('property: always-blocked ranges', () => {
  for (const cidr of ALWAYS_BLOCKED) {
    for (const [formName, format] of FORMS) {
      it(`rejects every ${cidr.name} address as ${formName}`, () => {
        fc.assert(
          fc.property(addressIn(cidr), (n) => {
            expect(checkIp(format(n)).allowed).toBe(false);
            expect(checkIp(format(n), { allowPrivate: true }).allowed).toBe(false);
          }),
          { numRuns: 300 },
        );
      });
    }
  }
});

describe('property: local-only ranges', () => {
  for (const cidr of LOCAL_ONLY) {
    for (const [formName, format] of FORMS) {
      it(`rejects ${cidr.name} as ${formName} by default, allows it with allowPrivate`, () => {
        fc.assert(
          fc.property(addressIn(cidr), (n) => {
            expect(checkIp(format(n)).allowed).toBe(false);
            expect(checkIp(format(n), { allowPrivate: true }).allowed).toBe(true);
          }),
          { numRuns: 300 },
        );
      });
    }
  }
});

describe('property: general behavior', () => {
  it('never throws, whatever the input string', () => {
    fc.assert(
      fc.property(fc.string(), (input) => {
        const result = checkIp(input);
        expect(typeof result.allowed).toBe('boolean');
      }),
      { numRuns: 1000 },
    );
  });

  it('only allows an IPv4 address that is outside every blocked range', () => {
    fc.assert(
      fc.property(fc.ipV4(), (ip) => {
        const result = checkIp(ip);
        if (result.allowed) {
          expect(inAny(toInt(ip), [...ALWAYS_BLOCKED, ...LOCAL_ONLY])).toBe(false);
        }
      }),
      { numRuns: 2000 },
    );
  });

  it('gives an allowed IPv6 address back in a form that is still allowed', () => {
    fc.assert(
      fc.property(fc.ipV6(), (ip) => {
        const result = checkIp(ip);
        if (result.allowed) {
          const again = checkIp(result.ip);
          expect(again).toEqual({ allowed: true, ip: result.ip });
        }
      }),
      { numRuns: 1000 },
    );
  });
});
