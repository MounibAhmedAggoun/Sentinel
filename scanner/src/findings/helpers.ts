import type { HttpHop } from '../http/types.js';
import type { ScanResult } from './types.js';

/**
 * The last response in the HTTP chain, or null if there is nothing reliable to judge.
 * When the chain ended in an error, the last hop may be a half-followed redirect,
 * so rules skip it instead of guessing.
 */
export function finalHop(scan: ScanResult): HttpHop | null {
  if (scan.http.error !== null) return null;
  return scan.http.hops.at(-1) ?? null;
}

/** Reads a header as a single string. Header names are lowercase. */
export function headerValue(hop: HttpHop, name: string): string | null {
  const value = hop.headers[name.toLowerCase()];
  if (Array.isArray(value)) return value.join(', ');
  return value ?? null;
}
