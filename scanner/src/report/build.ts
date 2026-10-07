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

/**
 * Set-Cookie values can be live session tokens, so reports keep only the
 * cookie name. The Secure/HttpOnly/SameSite flags are already stored
 * separately in each hop's "cookies" list.
 */
function redactHeaders(
  headers: Record<string, string | string[]>,
): Record<string, string | string[]> {
  const result: Record<string, string | string[]> = { ...headers };
  const setCookie = result['set-cookie'];
  if (setCookie !== undefined) {
    const lines = Array.isArray(setCookie) ? setCookie : [setCookie];
    result['set-cookie'] = lines.map((line) => `${line.split('=')[0]?.trim() ?? ''}=[redacted]`);
  }
  return result;
}

function redactHttp(result: HttpResult): HttpResult {
  return {
    ...result,
    hops: result.hops.map((hop) => ({ ...hop, headers: redactHeaders(hop.headers) })),
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
