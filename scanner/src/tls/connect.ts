import { isIP } from 'node:net';
import tls from 'node:tls';
import { analyzeCertificate } from './analyze.js';
import type { CertName, TlsError, TlsOutcome } from './types.js';

export interface TlsConnectOptions {
  /** The name the certificate should cover. */
  hostname: string;
  /** A validated IP. We connect to this and never look the hostname up again. */
  ip: string;
  port?: number;
  timeoutMs?: number;
}

function first(value: string | string[] | undefined): string | null {
  if (Array.isArray(value)) return value[0] ?? null;
  return value ?? null;
}

function toCertName(name: tls.Certificate | undefined): CertName {
  return { commonName: first(name?.CN), organization: first(name?.O) };
}

function rawName(name: tls.Certificate | undefined): string {
  if (!name || Object.keys(name).length === 0) return '';
  return JSON.stringify(Object.entries(name).sort());
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
export function connectTls(options: TlsConnectOptions): Promise<TlsOutcome> {
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

      const san = parseSan(cert.subjectaltname);
      const validTo = toIso(cert.valid_to);

      done({
        ok: true,
        result: {
          ip,
          protocol: socket.getProtocol() ?? null,
          cipher: socket.getCipher()?.name ?? null,
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
            subjectRaw: rawName(cert.subject),
            issuerRaw: rawName(cert.issuer),
            commonName: first(cert.subject?.CN),
            san,
          }),
        },
      });
    });
  });
}
