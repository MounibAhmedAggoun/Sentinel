import type { DnsError, DnsErrorCode } from './types.js';

const CODE_MAP: Record<string, DnsErrorCode> = {
  ENOTFOUND: 'NXDOMAIN',
  ENODATA: 'NODATA',
  ETIMEOUT: 'TIMEOUT',
  ETIMEDOUT: 'TIMEOUT',
  ESERVFAIL: 'SERVFAIL',
  EREFUSED: 'REFUSED',
};

/** Converts any thrown DNS error into a structured DnsError. */
export function toDnsError(err: unknown): DnsError {
  const nodeCode = (err as { code?: unknown } | null)?.code;
  const code = typeof nodeCode === 'string' ? (CODE_MAP[nodeCode] ?? 'UNKNOWN') : 'UNKNOWN';
  const message = err instanceof Error ? err.message : 'unknown DNS error';
  return { code, message };
}
