import { isIP } from 'node:net';
import tls from 'node:tls';
import type { TlsAnalysis } from './types.js';

const DAY_MS = 86_400_000;

export interface AnalysisInput {
  /** The name we connected to, which the certificate should cover. */
  hostname: string;
  /** ISO 8601 timestamp. */
  validTo: string;
  /** Full subject and issuer strings. A self-signed certificate has the same value for both. */
  subjectRaw: string;
  issuerRaw: string;
  commonName: string | null;
  san: string[];
}

function matchesHostname(input: AnalysisInput): boolean {
  const altNames = input.san
    .map((name) => (isIP(name) !== 0 ? `IP Address:${name}` : `DNS:${name}`))
    .join(', ');

  const cert = {
    subject: input.commonName === null ? {} : { CN: input.commonName },
    subjectaltname: altNames,
  } as unknown as tls.PeerCertificate;

  return tls.checkServerIdentity(input.hostname, cert) === undefined;
}

/**
 * Works out validity ourselves. The TLS connection does not verify certificates
 * (see docs/security-decisions.md), so every check here is our own.
 */
export function analyzeCertificate(input: AnalysisInput, now: Date = new Date()): TlsAnalysis {
  const validTo = Date.parse(input.validTo);
  const invalidDate = Number.isNaN(validTo);

  return {
    expired: invalidDate || validTo < now.getTime(),
    daysUntilExpiry: invalidDate ? 0 : Math.floor((validTo - now.getTime()) / DAY_MS),
    selfSigned: input.subjectRaw !== '' && input.subjectRaw === input.issuerRaw,
    hostnameMatches: matchesHostname(input),
  };
}
