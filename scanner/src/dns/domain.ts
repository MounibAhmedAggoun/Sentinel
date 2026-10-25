import { getDomain } from 'tldts';

/**
 * The registrable domain (e.g. "example.com" from "www.example.com", or
 * "example.co.uk" from "mail.example.co.uk"). Returns null for things tldts
 * can't parse (bare IPs, single-label names like "localhost").
 */
export function registrableDomain(hostname: string): string | null {
  return getDomain(hostname);
}

/**
 * Every ancestor of a hostname, from itself up to (and including) its
 * registrable domain, in that order. Used to walk up the tree for CAA
 * lookups per RFC 8659, and for the DMARC organizational-domain fallback.
 *
 * "www.mail.example.com" with registrable domain "example.com" gives:
 * ["www.mail.example.com", "mail.example.com", "example.com"]
 */
export function domainAncestors(hostname: string): string[] {
  const base = registrableDomain(hostname);
  if (base === null) return [hostname];

  const labels = hostname.split('.');
  const baseLabels = base.split('.').length;
  const ancestors: string[] = [];

  for (let i = 0; i <= labels.length - baseLabels; i++) {
    ancestors.push(labels.slice(i).join('.'));
  }

  return ancestors;
}
