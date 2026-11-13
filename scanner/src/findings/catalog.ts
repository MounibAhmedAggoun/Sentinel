import type { Severity } from '@sentinel/core';
import type { RuleId } from './ids.js';

export type RuleArea = 'http' | 'cookie' | 'tls' | 'dns' | 'tcp';

export interface CatalogEntry {
  id: RuleId;
  area: RuleArea;
  /** The finding title. Text in angle brackets changes from finding to finding. */
  title: string;
  /** Every severity this rule can report, lowest first. */
  severities: readonly Severity[];
  /** One sentence on what is observed. */
  summary: string;
}

/** One entry for every rule ID. A test checks that none is missing or repeated. */
export const RULE_CATALOG: readonly CatalogEntry[] = [
  {
    id: 'HTTP-001',
    area: 'http',
    title: 'Security header not observed: Content-Security-Policy',
    severities: ['low'],
    summary: 'No Content-Security-Policy header was seen in the response.',
  },
  {
    id: 'HTTP-002',
    area: 'http',
    title: 'Security header not observed: Strict-Transport-Security',
    severities: ['low'],
    summary: 'No Strict-Transport-Security header was seen in an HTTPS response.',
  },
  {
    id: 'HTTP-003',
    area: 'http',
    title: 'Security header not observed: X-Content-Type-Options',
    severities: ['low'],
    summary: 'The X-Content-Type-Options header was missing or not set to nosniff.',
  },
  {
    id: 'HTTP-004',
    area: 'http',
    title: 'Security header not observed: X-Frame-Options or CSP frame-ancestors',
    severities: ['low'],
    summary: 'Neither an X-Frame-Options header nor a CSP frame-ancestors directive was seen.',
  },
  {
    id: 'HTTP-005',
    area: 'http',
    title: 'Security header not observed: Referrer-Policy',
    severities: ['low'],
    summary: 'No Referrer-Policy header was seen in the response.',
  },
  {
    id: 'HTTP-006',
    area: 'http',
    title: 'Version information observed in Server header',
    severities: ['informational'],
    summary: 'The Server header contains version-like text.',
  },
  {
    id: 'HTTP-007',
    area: 'http',
    title: 'Version information observed in X-Powered-By header',
    severities: ['informational'],
    summary: 'The X-Powered-By header contains version-like text.',
  },
  {
    id: 'HTTP-008',
    area: 'http',
    title: 'Redirect from HTTP to HTTPS not observed',
    severities: ['low'],
    summary: 'A request over plain HTTP was answered without a redirect to HTTPS.',
  },
  {
    id: 'HTTP-009',
    area: 'http',
    title: 'Strict-Transport-Security observed with a short or missing max-age',
    severities: ['low'],
    summary: 'The Strict-Transport-Security header has no max-age value, or one below 180 days.',
  },
  {
    id: 'HTTP-010',
    area: 'http',
    title: 'Content-Security-Policy observed with weak script sources',
    severities: ['low'],
    summary:
      'The script sources in the Content-Security-Policy include unsafe-inline, unsafe-eval or a bare wildcard.',
  },
  {
    id: 'COOKIE-001',
    area: 'cookie',
    title: 'Cookie flag not observed: Secure',
    severities: ['low'],
    summary: 'A cookie set over HTTPS has no Secure flag.',
  },
  {
    id: 'COOKIE-002',
    area: 'cookie',
    title: 'Cookie flag not observed: HttpOnly',
    severities: ['low'],
    summary: 'A cookie has no HttpOnly flag.',
  },
  {
    id: 'COOKIE-003',
    area: 'cookie',
    title: 'Cookie flag not observed: SameSite',
    severities: ['low'],
    summary: 'A cookie has no SameSite attribute.',
  },
  {
    id: 'COOKIE-004',
    area: 'cookie',
    title: 'Cookie observed with SameSite=None but without Secure',
    severities: ['low'],
    summary: 'A cookie sets SameSite=None without the Secure flag.',
  },
  {
    id: 'TLS-001',
    area: 'tls',
    title: 'Certificate expiry date has passed',
    severities: ['high'],
    summary: 'The certificate expiry date is in the past.',
  },
  {
    id: 'TLS-002',
    area: 'tls',
    title: 'Certificate is close to its expiry date',
    severities: ['low', 'medium', 'high'],
    summary:
      'The certificate expires within 30 days: low up to 30 days, medium up to 14, high up to 7.',
  },
  {
    id: 'TLS-003',
    area: 'tls',
    title: 'Self-signed certificate observed',
    severities: ['medium'],
    summary: 'The certificate subject and issuer match, so it appears to be self-signed.',
  },
  {
    id: 'TLS-004',
    area: 'tls',
    title: 'Certificate does not list the scanned hostname',
    severities: ['medium'],
    summary: 'The certificate does not list the scanned name in its subject or alternative names.',
  },
  {
    id: 'TLS-005',
    area: 'tls',
    title: 'Certificate not trusted by the system certificate store',
    severities: ['medium'],
    summary:
      'The system certificate store did not trust the certificate, and no more specific finding already explains it.',
  },
  {
    id: 'TLS-006',
    area: 'tls',
    title: 'Outdated TLS protocol version accepted',
    severities: ['medium'],
    summary:
      'The server accepted a handshake pinned to TLS 1.0 or TLS 1.1. Checked only with --probe-legacy-tls.',
  },
  {
    id: 'TLS-007',
    area: 'tls',
    title: 'TLS 1.3 not observed as supported',
    severities: ['informational'],
    summary:
      'The server did not accept a handshake pinned to TLS 1.3. Checked only with --probe-legacy-tls.',
  },
  {
    id: 'DNS-001',
    area: 'dns',
    title: 'SPF record not observed',
    severities: ['low'],
    summary: 'No SPF record was seen in the TXT records of the scanned name.',
  },
  {
    id: 'DNS-002',
    area: 'dns',
    title: 'DMARC record not observed',
    severities: ['low'],
    summary: 'No DMARC record was seen for the scanned name.',
  },
  {
    id: 'DNS-003',
    area: 'dns',
    title: 'CAA record not observed',
    severities: ['informational'],
    summary: 'No CAA record was seen for the scanned name or its parent domains.',
  },
  {
    id: 'DNS-004',
    area: 'dns',
    title: 'SPF record observed that allows any sender',
    severities: ['medium'],
    summary: 'The SPF record ends in +all, which permits any server to send mail for the domain.',
  },
  {
    id: 'DNS-005',
    area: 'dns',
    title: 'DMARC record observed with a monitoring-only policy',
    severities: ['informational'],
    summary:
      'The DMARC policy is p=none, which reports failures but asks receivers to take no action.',
  },
  {
    id: 'DNS-006',
    area: 'dns',
    title: 'SPF record observed without an enforcing policy',
    severities: ['low'],
    summary: 'The SPF record ends in ?all, or has neither an all mechanism nor a redirect.',
  },
  {
    id: 'TCP-001',
    area: 'tcp',
    title: 'TCP port <port> observed open',
    severities: ['informational'],
    summary: 'A port on the allowlist accepted a TCP connection.',
  },
  {
    id: 'TCP-002',
    area: 'tcp',
    title: '<service> port <port> observed open',
    severities: ['low', 'medium'],
    summary:
      'A port for a sensitive service (FTP, Telnet, RDP, MySQL, PostgreSQL, Redis or MongoDB) accepted a TCP connection.',
  },
];
