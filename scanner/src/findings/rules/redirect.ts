import { RULE_IDS } from '../ids.js';
import type { Finding, Rule } from '../types.js';

/**
 * Checks what happens when the site is requested over plain HTTP.
 * Reads the separate http:// check (scan.httpPlain). Skips itself when that
 * check failed or never got a response, instead of guessing.
 */
export const redirectRules: Rule = (scan) => {
  const plain = scan.httpPlain;
  if (plain.error !== null) return [];

  const first = plain.hops[0];
  const final = plain.hops.at(-1);
  if (first === undefined || final === undefined) return [];
  if (!first.url.startsWith('http:')) return [];
  if (final.url.startsWith('https:')) return [];

  const finding: Finding = {
    ruleId: RULE_IDS.HTTP_NO_HTTPS_REDIRECT,
    title: 'Redirect from HTTP to HTTPS not observed',
    severity: 'low',
    description: `A request to ${first.url} was answered over plain HTTP and did not redirect to HTTPS. Visitors who use the http:// address may stay on an unencrypted connection.`,
    evidence: {
      startUrl: first.url,
      finalUrl: final.url,
      finalStatus: final.status,
      hops: plain.hops.length,
    },
    remediation:
      'Consider redirecting all HTTP requests to HTTPS, and pair it with an HSTS header once the whole site works over HTTPS.',
  };

  return [finding];
};
