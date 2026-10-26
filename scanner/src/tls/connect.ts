import { X509Certificate } from 'node:crypto';
import { isIP } from 'node:net';
import tls from 'node:tls';
import { analyzeCertificate } from './analyze.js';
import { probeLegacyProtocols } from './legacy-probe.js';
import type { CertName, TlsError, TlsOutcome } from './types.js';

export interface TlsConnectOptions {
  /** The name the certificate should cover. */
  hostname: string;
  /** A validated IP. We connect to this and never look the hostname up again. */
  ip: string;
  port?: number;
  timeoutMs?: number;
  /**
   * Pin the handshake to exactly one protocol version, to probe whether a
   * server still accepts it. Omit for a normal scan, which lets Node and the
   * server negotiate their best shared version as usual. Internal: used by
   * probeLegacyProtocols, not meant to be set directly by callers.
   */
  minVersion?: 'TLSv1' | 'TLSv1.1' | 'TLSv1.2' | 'TLSv1.3';
  /**
   * After the main handshake succeeds, also probe for legacy protocol
   * (TLSv1/1.1) and TLSv1.3 support with a few extra handshakes. Off by
   * default, since it's extra network activity beyond what a scan strictly
   * needs.
   */
  probeLegacy?: boolean;
}

function first(value: string | string[] | undefined): string | null {
  if (Array.isArray(value)) return value[0] ?? null;
  return value ?? null;
}

function toCertName(name: tls.Certificate | undefined): CertName {
  return { commonName: first(name?.CN), organization: first(name?.O) };
}

/**
 * Cryptographically self-signed: the certificate's subject equals its
 * issuer AND it verifies against its own public key. This is stronger than
 * comparing subject/issuer strings, which can't detect a forged subject
 * line or be fooled by formatting differences.
 */
function checkSelfSigned(raw: Buffer | undefined): boolean {
  if (raw === undefined) return false;
  try {
    const x509 = new X509Certificate(raw);
    return x509.subject === x509.issuer && x509.verify(x509.publicKey);
  } catch {
    return false;
  }
}

function toIso(value: string | undefined): string {
  const time = Date.parse(value ?? '');
  return Number.isNaN(time) ? '' : new Date(time).toISOString();
}

/** Turns "DNS:a.com, IP Address:1.2.3.4" into ["a.com", "1.2.3.4"]. */
export function parseSan(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(',')
    .map((entry) => entry.trim())
    .flatMap((entry) => {
      if (entry.startsWith('DNS:')) return [entry.slice(4)];
      if (entry.startsWith('IP Address:')) return [entry.slice(11)];
      return [];
    });
}

/**
 * Reads a server's certificate for OBSERVATION ONLY.
 * rejectUnauthorized is false so expired, self-signed, and mismatched
 * certificates can still be read and reported. No data is sent after the
 * handshake. See docs/security-decisions.md.
 */
function connectOnce(options: TlsConnectOptions): Promise<TlsOutcome> {
  const { hostname, ip, port = 443, timeoutMs = 5000 } = options;

  return new Promise((resolve) => {
    let settled = false;

    const done = (outcome: TlsOutcome): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(outcome);
    };
    const fail = (code: TlsError['code'], message: string): void =>
      done({ ok: false, error: { code, message } });

    const socket = tls.connect({
      host: ip,
      port,
      // SNI must be a hostname, not an IP address.
      ...(isIP(hostname) === 0 ? { servername: hostname } : {}),
      rejectUnauthorized: false,
      ...(options.minVersion !== undefined
        ? { minVersion: options.minVersion, maxVersion: options.minVersion }
        : {}),
    });

    socket.setTimeout(timeoutMs);
    socket.once('timeout', () => fail('TIMEOUT', `no response within ${timeoutMs}ms`));
    socket.once('error', (err: NodeJS.ErrnoException) =>
      fail(err.code === 'ETIMEDOUT' ? 'TIMEOUT' : 'CONNECTION_FAILED', err.message),
    );

    socket.once('secureConnect', () => {
      const cert = socket.getPeerCertificate();
      if (!cert || Object.keys(cert).length === 0) {
        fail('NO_CERTIFICATE', 'server presented no certificate');
        return;
      }

      const trust = {
        authorized: socket.authorized,
        error: socket.authorized ? null : (socket.authorizationError?.message ?? 'unknown'),
      };

      const san = parseSan(cert.subjectaltname);
      const validTo = toIso(cert.valid_to);

      done({
        ok: true,
        result: {
          ip,
          protocol: socket.getProtocol() ?? null,
          cipher: socket.getCipher()?.name ?? null,
          legacyProtocols: null,
          certificate: {
            subject: toCertName(cert.subject),
            issuer: toCertName(cert.issuer),
            san,
            validFrom: toIso(cert.valid_from),
            validTo,
            serialNumber: cert.serialNumber,
            fingerprint256: cert.fingerprint256,
          },
          analysis: analyzeCertificate({
            hostname,
            validTo,
            selfSigned: checkSelfSigned(cert.raw),
            commonName: first(cert.subject?.CN),
            san,
            trust,
          }),
        },
      });
    });
  });
}

/**
 * Connects once for the main certificate read, then, if requested and that
 * connection succeeded, runs the extra legacy-protocol probe (a few more
 * handshakes pinned to specific versions) and merges the result in.
 */
export async function connectTls(options: TlsConnectOptions): Promise<TlsOutcome> {
  const outcome = await connectOnce(options);
  if (!outcome.ok || options.probeLegacy !== true) return outcome;

  const legacyProtocols = await probeLegacyProtocols(
    options.ip,
    options.hostname,
    options.port ?? 443,
  );

  return { ok: true, result: { ...outcome.result, legacyProtocols } };
}
