import { describe, expect, it } from 'vitest';
import type { DnsResult } from '../../dns/types.js';
import { makeScan } from '../fixtures.js';
import { RULE_IDS } from '../ids.js';
import type { ScanResult } from '../types.js';
import { dnsRules } from './dns.js';

function withDns(overrides: Partial<DnsResult>): ScanResult {
  const base = makeScan();
  return { ...base, dns: { ...base.dns, ...overrides } };
}

const NODATA = { ok: false, error: { code: 'NODATA', message: 'no data' } } as const;
const TIMEOUT = { ok: false, error: { code: 'TIMEOUT', message: 'slow' } } as const;
const SERVFAIL = { ok: false, error: { code: 'SERVFAIL', message: 'failed' } } as const;

const ids = (scan: ScanResult): string[] => dnsRules(scan).map((f) => f.ruleId);

describe('dnsRules: clean domain', () => {
  it('produces nothing when SPF, DMARC and CAA are all present', () => {
    expect(dnsRules(makeScan())).toEqual([]);
  });
});

describe('dnsRules: IP address targets', () => {
  const noRecords = { spf: null, dmarc: null, txt: NODATA, dmarcTxt: NODATA, caa: NODATA } as const;

  it('produces nothing for an IPv4 target, even with no SPF, DMARC or CAA records', () => {
    expect(dnsRules(withDns({ hostname: '127.0.0.1', ...noRecords }))).toEqual([]);
  });

  it('produces nothing for an IPv6 target', () => {
    expect(dnsRules(withDns({ hostname: '2606:4700:4700::1111', ...noRecords }))).toEqual([]);
  });

  it('still judges a real domain name with no records', () => {
    expect(ids(withDns({ hostname: 'example.com', ...noRecords }))).toEqual(
      expect.arrayContaining([
        RULE_IDS.DNS_SPF_MISSING,
        RULE_IDS.DNS_DMARC_MISSING,
        RULE_IDS.DNS_CAA_MISSING,
      ]),
    );
  });
});

describe('dnsRules: SPF', () => {
  it('reports a missing SPF record when TXT clearly has none', () => {
    const scan = withDns({ spf: null, txt: { ok: true, records: ['hello'] } });
    const findings = dnsRules(scan);

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.DNS_SPF_MISSING]);
    expect(findings[0]).toMatchObject({ severity: 'low', evidence: { present: false } });
    expect(findings[0]?.remediation).not.toBe('');
  });

  it('reports a missing SPF record when TXT lookup returned NODATA', () => {
    expect(ids(withDns({ spf: null, txt: NODATA }))).toEqual([RULE_IDS.DNS_SPF_MISSING]);
  });

  it('stays silent when the TXT lookup timed out', () => {
    expect(ids(withDns({ spf: null, txt: TIMEOUT }))).toEqual([]);
  });

  it('reports "+all" with its own rule ID', () => {
    const findings = dnsRules(withDns({ spf: { raw: 'v=spf1 +all', all: '+all' } }));

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.DNS_SPF_PERMISSIVE]);
    expect(findings[0]?.severity).toBe('medium');
  });

  it.each(['-all', '~all'] as const)('accepts an SPF record ending in %s', (all) => {
    expect(dnsRules(withDns({ spf: { raw: `v=spf1 ${all}`, all } }))).toEqual([]);
  });

  it('flags an SPF record ending in ?all as not enforcing', () => {
    const findings = dnsRules(withDns({ spf: { raw: 'v=spf1 ?all', all: '?all' } }));

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.DNS_SPF_NO_ENFORCEMENT]);
    expect(findings[0]?.evidence).toMatchObject({ all: '?all', hasRedirect: false });
  });

  it('flags an SPF record with no all mechanism and no redirect', () => {
    expect(
      dnsRules(withDns({ spf: { raw: 'v=spf1 include:_spf.example.net', all: null } })).map(
        (f) => f.ruleId,
      ),
    ).toEqual([RULE_IDS.DNS_SPF_NO_ENFORCEMENT]);
  });

  it('accepts an SPF record that uses redirect= instead of all', () => {
    expect(
      dnsRules(withDns({ spf: { raw: 'v=spf1 redirect=_spf.example.net', all: null } })),
    ).toEqual([]);
  });
});

describe('dnsRules: DMARC', () => {
  it('reports a missing DMARC record when the lookup clearly found none', () => {
    const scan = withDns({ dmarc: null, dmarcTxt: NODATA });
    const findings = dnsRules(scan);

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.DNS_DMARC_MISSING]);
    expect(findings[0]?.evidence).toEqual({ name: '_dmarc.example.com', present: false });
  });

  it('stays silent when the DMARC lookup timed out', () => {
    expect(ids(withDns({ dmarc: null, dmarcTxt: TIMEOUT }))).toEqual([]);
  });

  it('stays silent when the DMARC lookup got SERVFAIL', () => {
    expect(ids(withDns({ dmarc: null, dmarcTxt: SERVFAIL }))).toEqual([]);
  });

  it('reports p=none as informational with its own rule ID', () => {
    const findings = dnsRules(withDns({ dmarc: { raw: 'v=DMARC1; p=none', policy: 'none' } }));

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.DNS_DMARC_MONITORING_ONLY]);
    expect(findings[0]?.severity).toBe('informational');
  });

  it.each(['quarantine', 'reject'] as const)('accepts p=%s', (policy) => {
    expect(dnsRules(withDns({ dmarc: { raw: `v=DMARC1; p=${policy}`, policy } }))).toEqual([]);
  });
});

describe('dnsRules: CAA', () => {
  it('reports a missing CAA record as informational', () => {
    const findings = dnsRules(withDns({ caa: NODATA }));

    expect(findings.map((f) => f.ruleId)).toEqual([RULE_IDS.DNS_CAA_MISSING]);
    expect(findings[0]?.severity).toBe('informational');
  });

  it('reports a missing CAA record when the lookup returned an empty list', () => {
    expect(ids(withDns({ caa: { ok: true, records: [] } }))).toEqual([RULE_IDS.DNS_CAA_MISSING]);
  });

  it('stays silent when the CAA lookup timed out', () => {
    expect(ids(withDns({ caa: TIMEOUT }))).toEqual([]);
  });
});

describe('dnsRules: wording', () => {
  it('never claims a vulnerability', () => {
    const scan = withDns({
      spf: null,
      txt: NODATA,
      dmarc: null,
      dmarcTxt: NODATA,
      caa: NODATA,
    });

    for (const finding of dnsRules(scan)) {
      expect(`${finding.title} ${finding.description}`.toLowerCase()).not.toContain('vulnerab');
    }
  });
});
