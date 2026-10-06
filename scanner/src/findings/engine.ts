import { cookieRules } from './rules/cookies.js';
import { disclosureRules } from './rules/disclosure.js';
import { dnsRules } from './rules/dns.js';
import { headerRules } from './rules/headers.js';
import { redirectRules } from './rules/redirect.js';
import { tcpRules } from './rules/tcp.js';
import { tlsRules } from './rules/tls.js';
import type { Finding, Rule, ScanResult } from './types.js';

/** Every rule family, in the order their findings are listed within a severity. */
export const ALL_RULES: readonly Rule[] = [
  headerRules,
  disclosureRules,
  redirectRules,
  cookieRules,
  tlsRules,
  dnsRules,
  tcpRules,
];

const SEVERITY_ORDER: Record<Finding['severity'], number> = {
  high: 0,
  medium: 1,
  low: 2,
  informational: 3,
};

/**
 * Runs every rule over one scan result. Pure: the same scan always gives the
 * same findings in the same order, most severe first.
 */
export function evaluate(scan: ScanResult, rules: readonly Rule[] = ALL_RULES): Finding[] {
  const findings = rules.flatMap((rule) => rule(scan));

  // Array.prototype.sort is stable, so ties keep rule order.
  return findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}
