import { isIP } from 'node:net';
import type { DnsLookup } from '../../dns/types.js';
import { RULE_IDS } from '../ids.js';
import type { Finding, Rule } from '../types.js';

/**
 * A lookup that failed for a reason other than "no such record" tells us nothing,
 * so rules only conclude "not observed" when the DNS server clearly answered.
 */
function clearlyAbsent<T>(lookup: DnsLookup<T>): boolean {
  if (lookup.ok) return lookup.records.length === 0;
  return lookup.error.code === 'NODATA' || lookup.error.code === 'NXDOMAIN';
}

/** True when the DNS server clearly answered, even if the answer had no matching record. */
function answered<T>(lookup: DnsLookup<T>): boolean {
  return lookup.ok || lookup.error.code === 'NODATA' || lookup.error.code === 'NXDOMAIN';
}

export const dnsRules: Rule = (scan) => {
  const { dns } = scan;

  // SPF, DMARC and CAA are domain records. An IP address has none, so judging
  // one would only produce false "not observed" findings.
  if (isIP(dns.hostname) !== 0) return [];

  const findings: Finding[] = [];

  // SPF lives in the TXT records of the domain itself.
  if (dns.spf === null) {
    if (answered(dns.txt)) {
      findings.push({
        ruleId: RULE_IDS.DNS_SPF_MISSING,
        title: 'SPF record not observed',
        severity: 'low',
        description: `No SPF record was observed in the TXT records for ${dns.hostname}. SPF lists which servers may send email for a domain, and helps receivers spot forged mail. It matters most for domains that send or receive email.`,
        evidence: { hostname: dns.hostname, present: false },
        remediation:
          'If this domain sends email, consider publishing an SPF record. If it never sends email, a record such as "v=spf1 -all" says so.',
      });
    }
  } else if (dns.spf.all === '+all') {
    findings.push({
      ruleId: RULE_IDS.DNS_SPF_PERMISSIVE,
      title: 'SPF record observed that allows any sender',
      severity: 'medium',
      description: `The SPF record for ${dns.hostname} ends in "+all", which permits any server to send email for the domain. That defeats the purpose of SPF.`,
      evidence: { hostname: dns.hostname, raw: dns.spf.raw.slice(0, 200), all: dns.spf.all },
      remediation:
        'Review the SPF record and end it with "-all" or "~all", listing only the servers that should send email.',
    });
  }

  // SPF observed but not enforcing: ends in "?all", or has no "all" and no redirect.
  if (dns.spf !== null) {
    const hasRedirect = /(^|\s)redirect=/i.test(dns.spf.raw);
    const neutral = dns.spf.all === '?all';
    const noVerdict = dns.spf.all === null && !hasRedirect;
    if (neutral || noVerdict) {
      findings.push({
        ruleId: RULE_IDS.DNS_SPF_NO_ENFORCEMENT,
        title: 'SPF record observed without an enforcing policy',
        severity: 'low',
        description: neutral
          ? `The SPF record for ${dns.hostname} ends in "?all", which tells receivers to treat every sender as neutral. Mail from unlisted servers is neither passed nor failed.`
          : `The SPF record for ${dns.hostname} has no "all" mechanism and no redirect, so receivers get no verdict for servers that are not listed.`,
        evidence: {
          hostname: dns.hostname,
          raw: dns.spf.raw.slice(0, 200),
          all: dns.spf.all,
          hasRedirect,
        },
        remediation:
          'Review the SPF record and end it with "-all" or "~all", listing only the servers that should send email.',
      });
    }
  }

  // More than one SPF record is a permanent error under the SPF standard.
  if (dns.txt.ok) {
    const spfRecords = dns.txt.records.filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));
    if (spfRecords.length > 1) {
      findings.push({
        ruleId: RULE_IDS.DNS_SPF_MULTIPLE_RECORDS,
        title: 'More than one SPF record observed',
        severity: 'low',
        description: `${spfRecords.length} SPF records were observed in the TXT records for ${dns.hostname}. A name may have only one, and receivers may treat several as a permanent error, so SPF checks for this domain may fail.`,
        evidence: {
          hostname: dns.hostname,
          count: spfRecords.length,
          records: spfRecords.map((r) => r.slice(0, 200)),
        },
        remediation:
          'Merge the records into one SPF record, combining their mechanisms, and remove the others.',
      });
    }
  }

  // SPF allows at most 10 mechanisms that need a DNS lookup. Only the record itself
  // is counted here: included records are not followed, so the real total can be higher.
  if (dns.spf !== null) {
    const lookupTerms = dns.spf.raw
      .trim()
      .split(/\s+/)
      .slice(1)
      .filter(
        (term) =>
          /^[+\-~?]?(include|a|mx|ptr|exists)(?=[:/]|$)/i.test(term) || /^redirect=/i.test(term),
      );
    if (lookupTerms.length > 10) {
      findings.push({
        ruleId: RULE_IDS.DNS_SPF_TOO_MANY_LOOKUPS,
        title: 'SPF record observed with more than 10 DNS lookups',
        severity: 'low',
        description: `The SPF record for ${dns.hostname} has ${lookupTerms.length} mechanisms that need a DNS lookup, and the SPF standard allows at most 10. Receivers may treat the record as a permanent error. Included records were not followed, so the real total can be higher.`,
        evidence: {
          hostname: dns.hostname,
          lookupMechanisms: lookupTerms.length,
          limit: 10,
          raw: dns.spf.raw.slice(0, 200),
        },
        remediation:
          'Reduce the number of include, a, mx, ptr, exists and redirect terms, for example by removing unused senders or replacing includes with ip4 or ip6 ranges.',
      });
    }
  }

  // DMARC lives at _dmarc.<hostname>.
  if (dns.dmarc === null) {
    if (answered(dns.dmarcTxt)) {
      findings.push({
        ruleId: RULE_IDS.DNS_DMARC_MISSING,
        title: 'DMARC record not observed',
        severity: 'low',
        description: `No DMARC record was observed at _dmarc.${dns.hostname}, or at the organizational domain's DMARC record. DMARC tells receivers what to do with mail that fails SPF or DKIM checks, and gives the domain owner reports about it.`,
        evidence: { name: `_dmarc.${dns.hostname}`, present: false },
        remediation:
          'Consider publishing a DMARC record, starting with p=none to collect reports before moving to quarantine or reject.',
      });
    }
  } else if (dns.dmarc.policy === 'none') {
    findings.push({
      ruleId: RULE_IDS.DNS_DMARC_MONITORING_ONLY,
      title: 'DMARC record observed with a monitoring-only policy',
      severity: 'informational',
      description: `The DMARC record for ${dns.hostname} uses p=none, which reports failures but does not ask receivers to act on them. This is a common first step.`,
      evidence: { raw: dns.dmarc.raw.slice(0, 200), policy: dns.dmarc.policy },
      remediation: 'Once reports look clean, consider moving to p=quarantine or p=reject.',
    });
  }

  if (clearlyAbsent(dns.caa)) {
    findings.push({
      ruleId: RULE_IDS.DNS_CAA_MISSING,
      title: 'CAA record not observed',
      severity: 'informational',
      description: `No CAA record was observed for ${dns.hostname} or any of its parent domains. CAA records restrict which certificate authorities may issue certificates for a domain.`,
      evidence: { hostname: dns.hostname, present: false },
      remediation: 'Consider adding a CAA record naming the certificate authorities you use.',
    });
  }

  return findings;
};
