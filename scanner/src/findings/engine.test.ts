import { describe, expect, it } from 'vitest';
import { ALL_RULES, evaluate } from './engine.js';
import { makeScan, scanWithHeaders } from './fixtures.js';
import { RULE_IDS } from './ids.js';
import type { Finding, ScanResult } from './types.js';

/** A scan with problems in every area. */
function badScan(): ScanResult {
  const base = scanWithHeaders({ server: 'Apache/2.4.41 (Ubuntu)' });
  const hop = base.http.hops[0]!;
  if (!base.tls.ok) throw new Error('fixture TLS should be ok');

  return {
    ...base,
    http: {
      ...base.http,
      hops: [
        { ...hop, cookies: [{ name: 'sid', secure: false, httpOnly: false, sameSite: null }] },
      ],
    },
    httpPlain: {
      startUrl: 'http://example.com/',
      finalUrl: 'http://example.com/',
      hops: [
        {
          url: 'http://example.com/',
          status: 200,
          headers: {},
          cookies: [],
          remoteIp: '93.184.216.34',
          timingMs: 5,
        },
      ],
      error: null,
    },
    tls: {
      ok: true,
      result: {
        ...base.tls.result,
        analysis: { expired: true, daysUntilExpiry: -3, selfSigned: true, hostnameMatches: false },
      },
    },
    dns: {
      ...base.dns,
      spf: null,
      txt: { ok: true, records: [] },
      dmarc: null,
      dmarcTxt: { ok: false, error: { code: 'NODATA', message: 'no data' } },
      caa: { ok: false, error: { code: 'NODATA', message: 'no data' } },
    },
    tcp: {
      ok: true,
      result: { ip: '93.184.216.34', ports: [{ port: 3306, state: 'open', timingMs: 5 }] },
    },
  };
}

describe('rule ID registry', () => {
  it('has no duplicate IDs', () => {
    const ids = Object.values(RULE_IDS);

    expect(new Set(ids).size).toBe(ids.length);
  });

  it('uses the FAMILY-NNN format', () => {
    for (const id of Object.values(RULE_IDS)) {
      expect(id).toMatch(/^[A-Z]+-\d{3}$/);
    }
  });
});

describe('evaluate', () => {
  it('produces no findings for a clean scan', () => {
    expect(evaluate(makeScan())).toEqual([]);
  });

  it('only emits IDs that exist in the registry', () => {
    const registry = new Set<string>(Object.values(RULE_IDS));

    for (const finding of evaluate(badScan())) {
      expect(registry.has(finding.ruleId)).toBe(true);
    }
  });

  it('gives every finding evidence and remediation', () => {
    for (const finding of evaluate(badScan())) {
      expect(Object.keys(finding.evidence).length).toBeGreaterThan(0);
      expect(finding.remediation).not.toBe('');
      expect(finding.title).not.toBe('');
    }
  });

  it('never claims a vulnerability', () => {
    for (const finding of evaluate(badScan())) {
      expect(`${finding.title} ${finding.description}`.toLowerCase()).not.toContain('vulnerab');
    }
  });

  it('sorts findings from most to least severe', () => {
    const order: Finding['severity'][] = ['high', 'medium', 'low', 'informational'];
    const ranks = evaluate(badScan()).map((f) => order.indexOf(f.severity));

    expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
  });

  it('is deterministic: the same scan gives the same findings', () => {
    expect(evaluate(badScan())).toEqual(evaluate(badScan()));
  });

  it('matches a snapshot of rule IDs and severities for a bad scan', () => {
    expect(evaluate(badScan()).map((f) => `${f.severity} ${f.ruleId}`)).toMatchSnapshot();
  });

  it('runs only the rules it is given', () => {
    expect(evaluate(badScan(), [])).toEqual([]);
    expect(
      evaluate(badScan(), ALL_RULES.slice(0, 1)).every((f) => f.ruleId.startsWith('HTTP-')),
    ).toBe(true);
  });
});
