import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { readSignatureAlgorithm } from './signature.js';

let dir: string;
const certs = new Map<string, Buffer>();

function cert(name: string): Buffer {
  const found = certs.get(name);
  if (found === undefined) throw new Error(`no test certificate named ${name}`);
  return found;
}

/** Makes a throwaway self-signed certificate with the real openssl and returns its DER bytes. */
function makeCert(name: string, keyArgs: string[], digest: string[]): void {
  const key = path.join(dir, `${name}.key`);
  const pem = path.join(dir, `${name}.pem`);
  execFileSync(
    'openssl',
    [
      'req',
      '-x509',
      ...keyArgs,
      '-nodes',
      '-keyout',
      key,
      '-out',
      pem,
      '-days',
      '2',
      '-subj',
      '/CN=localhost',
      ...digest,
    ],
    { stdio: 'ignore' },
  );
  certs.set(name, new X509Certificate(readFileSync(pem)).raw);
}

beforeAll(() => {
  dir = mkdtempSync(path.join(tmpdir(), 'sentinel-sig-'));
  makeCert('rsa256', ['-newkey', 'rsa:2048'], ['-sha256']);
  makeCert('rsa384', ['-newkey', 'rsa:2048'], ['-sha384']);
  makeCert('rsa512', ['-newkey', 'rsa:2048'], ['-sha512']);
  makeCert('ec256', ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1'], ['-sha256']);
  makeCert('ec384', ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:secp384r1'], ['-sha384']);
  makeCert('ed25519', ['-newkey', 'ed25519'], []);
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** Copies a real RSA/SHA-256 certificate and changes the last byte of its signature OID. */
function withOidLastByte(lastByte: number): Buffer {
  const raw = Buffer.from(cert('rsa256'));
  const oid = Buffer.from('2a864886f70d01010b', 'hex');
  const at = raw.lastIndexOf(oid);
  expect(at).toBeGreaterThan(0);
  raw[at + oid.length - 1] = lastByte;
  return raw;
}

describe('readSignatureAlgorithm', () => {
  it.each([
    ['rsa256', 'sha256WithRSAEncryption'],
    ['rsa384', 'sha384WithRSAEncryption'],
    ['rsa512', 'sha512WithRSAEncryption'],
    ['ec256', 'ecdsa-with-SHA256'],
    ['ec384', 'ecdsa-with-SHA384'],
    ['ed25519', 'ED25519'],
  ])('reads %s from a real certificate', (name, expected) => {
    expect(readSignatureAlgorithm(cert(name))).toBe(expected);
  });

  it.each(['rsa256', 'rsa384', 'rsa512', 'ec256', 'ec384', 'ed25519'])(
    'agrees with Node on %s when Node gives an answer',
    (name) => {
      const raw = cert(name);
      const nodeValue = new X509Certificate(raw).signatureAlgorithm;

      if (nodeValue !== undefined) expect(readSignatureAlgorithm(raw)).toBe(nodeValue);
    },
  );

  it('reads SHA-1 and MD5 signatures', () => {
    expect(readSignatureAlgorithm(withOidLastByte(0x05))).toBe('sha1WithRSAEncryption');
    expect(readSignatureAlgorithm(withOidLastByte(0x04))).toBe('md5WithRSAEncryption');
  });

  it('returns the dotted OID for an algorithm it does not know', () => {
    expect(readSignatureAlgorithm(withOidLastByte(0x7f))).toBe('1.2.840.113549.1.1.127');
  });

  it('returns null for bytes that are not a certificate', () => {
    expect(readSignatureAlgorithm(Buffer.alloc(0))).toBeNull();
    expect(readSignatureAlgorithm(Buffer.from('hello world'))).toBeNull();
    expect(readSignatureAlgorithm(Buffer.from([0x30, 0x80, 0x00]))).toBeNull();
  });

  it('returns null for a truncated certificate and never throws', () => {
    const raw = cert('rsa256');

    for (let length = 0; length < raw.length; length += 5) {
      expect(readSignatureAlgorithm(raw.subarray(0, length))).toBeNull();
    }
  });
});
