import { RULE_IDS } from '../ids.js';
import { finalHop, headerValue } from '../helpers.js';
import type { Finding, Rule } from '../types.js';

/** Matches version-like text such as "2.4.41" or "1.18". */
const VERSION = /\d+\.\d+/;

/** Header values come from the target, so cap their length before storing them. */
const MAX_EVIDENCE_LENGTH = 200;

function disclosure(ruleId: string, header: string, value: string, url: string): Finding {
  return {
    ruleId,
    title: `Version information observed in ${header} header`,
    severity: 'informational',
    description: `The ${header} header on ${url} includes version-like text. Version details can help someone look up issues known for that exact software.`,
    evidence: { header, value: value.slice(0, MAX_EVIDENCE_LENGTH), url },
    remediation: `Consider configuring the server to remove version details from the ${header} header. Keeping the software up to date matters more than hiding its version.`,
  };
}

export const disclosureRules: Rule = (scan) => {
  const hop = finalHop(scan);
  if (hop === null) return [];

  const findings: Finding[] = [];

  const server = headerValue(hop, 'server');
  if (server !== null && VERSION.test(server)) {
    findings.push(disclosure(RULE_IDS.HTTP_SERVER_VERSION_DISCLOSED, 'Server', server, hop.url));
  }

  const poweredBy = headerValue(hop, 'x-powered-by');
  if (poweredBy !== null && VERSION.test(poweredBy)) {
    findings.push(
      disclosure(RULE_IDS.HTTP_POWERED_BY_DISCLOSED, 'X-Powered-By', poweredBy, hop.url),
    );
  }

  return findings;
};
