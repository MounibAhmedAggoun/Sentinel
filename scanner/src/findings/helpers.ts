import type { HttpHop, HttpResult } from '../http/types.js';
import type { ScanResult } from './types.js';

/**
 * The HTTP chain the rules should judge, or null if there is nothing reliable.
 *
 * Normally this is the https:// chain. If nothing accepted the https:// connection
 * (CONNECTION_FAILED) but the separate http:// check completed cleanly, the site
 * only answers on plain HTTP, so that chain is judged instead and findings name
 * the http:// URL. Any other failure (timeout, TLS error, blocked target) tells
 * us nothing about what the site serves, so rules skip it instead of guessing.
 */
export function judgedChain(scan: ScanResult): HttpResult | null {
  if (scan.http.error === null) return scan.http;

  const httpsUnreachable = scan.http.error.code === 'CONNECTION_FAILED';
  if (httpsUnreachable && scan.httpPlain.error === null && scan.httpPlain.hops.length > 0) {
    return scan.httpPlain;
  }
  return null;
}

/**
 * The last response in the judged chain, or null if there is nothing reliable to judge.
 * When the chain ended in an error, the last hop may be a half-followed redirect,
 * so rules skip it instead of guessing.
 */
export function finalHop(scan: ScanResult): HttpHop | null {
  return judgedChain(scan)?.hops.at(-1) ?? null;
}

/** Reads a header as a single string. Header names are lowercase. */
export function headerValue(hop: HttpHop, name: string): string | null {
  const value = hop.headers[name.toLowerCase()];
  if (Array.isArray(value)) return value.join(', ');
  return value ?? null;
}
