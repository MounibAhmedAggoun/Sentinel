import type { Finding, ScanResult } from '../findings/types.js';
import type { HttpResult } from '../http/types.js';
import { reportSchema, SCHEMA_VERSION, type Report } from './schema.js';

export interface BuildReportInput {
  scan: ScanResult;
  findings: Finding[];
  startedAt: Date;
  finishedAt: Date;
  toolVersion: string;
}

type ReportError = Report['errors'][number];

const HEADER_ALLOWLIST = new Set([
  'server',
  'x-powered-by',
  'via',
  'content-type',
  'cache-control',
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'cross-origin-embedder-policy',
  'location',
  'alt-svc',
]);

function redactHeaders(
  headers: Record<string, string | string[]>,
): Record<string, string | string[]> {
  const result: Record<string, string | string[]> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (!HEADER_ALLOWLIST.has(name.toLowerCase())) continue;
    // The Location header's value is itself a URL, and can carry a secret
    // in its query string (an OAuth callback token, a signed URL), so it
    // needs the same redaction as the top-level URL fields.
    if (name.toLowerCase() === 'location') {
      result[name] = Array.isArray(value) ? value.map(redactUrl) : redactUrl(value);
    } else {
      result[name] = value;
    }
  }
  return result;
}

/**
 * Keeps the origin and path of a URL, but strips the query string. A query
 * string can carry secrets (an OAuth callback token, a signed URL), while
 * the scheme/host/path is what rules and readers actually need.
 */
function redactUrl(url: string): string {
  try {
    const parsed = new URL(url);
    const hasQuery = parsed.search !== '';
    parsed.search = '';
    return hasQuery ? `${parsed.toString()}?[redacted]` : parsed.toString();
  } catch {
    // Not a parseable absolute URL (shouldn't normally happen here); keep as is.
    return url;
  }
}

function redactHttp(result: HttpResult): HttpResult {
  return {
    ...result,
    startUrl: redactUrl(result.startUrl),
    finalUrl: result.finalUrl === null ? null : redactUrl(result.finalUrl),
    hops: result.hops.map((hop) => ({
      ...hop,
      url: redactUrl(hop.url),
      headers: redactHeaders(hop.headers),
    })),
  };
}

/** Problems with the scan itself. "No such record" is a normal DNS answer, not an error. */
function collectErrors(scan: ScanResult): ReportError[] {
  const errors: ReportError[] = [];

  for (const key of ['a', 'aaaa', 'mx', 'ns', 'txt', 'caa', 'dmarcTxt'] as const) {
    const lookup = scan.dns[key];
    if (!lookup.ok && lookup.error.code !== 'NODATA' && lookup.error.code !== 'NXDOMAIN') {
      errors.push({ module: `dns.${key}`, ...lookup.error });
    }
  }
  if (scan.http.error !== null) errors.push({ module: 'http', ...scan.http.error });
  if (scan.httpPlain.error !== null) errors.push({ module: 'httpPlain', ...scan.httpPlain.error });
  if (!scan.tcp.ok) errors.push({ module: 'tcp', ...scan.tcp.error });
  if (!scan.tls.ok) errors.push({ module: 'tls', ...scan.tls.error });

  return errors;
}

/**
 * Builds the report and validates it against the schema before returning,
 * so Sentinel can never write a report that breaks its own format.
 */
export function buildReport(input: BuildReportInput): Report {
  const { scan, findings, startedAt, finishedAt, toolVersion } = input;

  return reportSchema.parse({
    schemaVersion: SCHEMA_VERSION,
    tool: { name: 'sentinel', version: toolVersion },
    target: scan.target,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    durationMs: Math.max(0, finishedAt.getTime() - startedAt.getTime()),
    dns: scan.dns,
    http: redactHttp(scan.http),
    httpPlain: redactHttp(scan.httpPlain),
    tcp: scan.tcp,
    tls: scan.tls,
    findings,
    errors: collectErrors(scan),
  });
}
