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

  // DMARC lives at _dmarc.<hostname>.
  if (dns.dmarc === null) {
    if (answered(dns.dmarcTxt)) {
      findings.push({
        ruleId: RULE_IDS.DNS_DMARC_MISSING,
        title: 'DMARC record not observed',
        severity: 'low',
        description: `No DMARC record was observed at _dmarc.${dns.hostname}. DMARC tells receivers what to do with mail that fails SPF or DKIM checks, and gives the domain owner reports about it.`,
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
      description: `No CAA record was observed for ${dns.hostname}. CAA records restrict which certificate authorities may issue certificates for a domain.`,
      evidence: { hostname: dns.hostname, present: false },
      remediation: 'Consider adding a CAA record naming the certificate authorities you use.',
    });
  }

  return findings;
};
