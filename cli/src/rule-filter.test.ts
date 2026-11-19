import { describe, expect, it } from 'vitest';
import { evaluate, RULE_CATALOG } from '@sentinel/scanner';
import { makeScan } from '../../scanner/src/findings/fixtures.js';
import { filterFindings, markExpectedPorts, parseRuleList } from './rule-filter.js';

const KNOWN = RULE_CATALOG.map((entry) => entry.id);

describe('parseRuleList', () => {
  it('accepts a single known ID', () => {
    expect(parseRuleList('HTTP-001', KNOWN)).toEqual({ ok: true, ids: ['HTTP-001'] });
  });

  it('accepts several known IDs and removes repeats', () => {
    expect(parseRuleList('HTTP-001,TLS-002,HTTP-001', KNOWN)).toEqual({
      ok: true,
      ids: ['HTTP-001', 'TLS-002'],
    });
  });

  it.each(['', ',', 'HTTP-001,', ',HTTP-001', 'HTTP-001,,TLS-002'])('rejects %j', (raw) => {
    expect(parseRuleList(raw, KNOWN).ok).toBe(false);
  });

  it.each(['http-001', 'HTTP-999', 'HTTP-001 ', ' HTTP-001', 'HTTP-001;TLS-002', 'nonsense'])(
    'rejects the unknown ID %j',
    (raw) => {
      expect(parseRuleList(raw, KNOWN).ok).toBe(false);
    },
  );

  it('names the unknown rules in the error', () => {
    const result = parseRuleList('HTTP-001,NOPE-1,ALSO-2', KNOWN);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('unknown rule(s): NOPE-1, ALSO-2');
  });
});

describe('filterFindings', () => {
  const findings = [{ ruleId: 'HTTP-001' }, { ruleId: 'TLS-002' }, { ruleId: 'DNS-003' }];

  it('keeps everything when no filter is given', () => {
    expect(filterFindings(findings, {})).toEqual(findings);
  });

  it('keeps only the listed rules with only', () => {
    expect(filterFindings(findings, { only: ['TLS-002', 'DNS-003'] })).toEqual([
      { ruleId: 'TLS-002' },
      { ruleId: 'DNS-003' },
    ]);
  });

  it('drops the listed rules with skip', () => {
    expect(filterFindings(findings, { skip: ['HTTP-001'] })).toEqual([
      { ruleId: 'TLS-002' },
      { ruleId: 'DNS-003' },
    ]);
  });

  it('keeps the original order', () => {
    expect(filterFindings(findings, { only: ['DNS-003', 'HTTP-001'] })).toEqual([
      { ruleId: 'HTTP-001' },
      { ruleId: 'DNS-003' },
    ]);
  });

  it('returns nothing when only matches no finding', () => {
    expect(filterFindings(findings, { only: ['TCP-001'] })).toEqual([]);
  });
});

describe('markExpectedPorts', () => {
  const scanWithOpen = (ports: number[]) => ({
    ...makeScan(),
    tcp: {
      ok: true as const,
      result: {
        ip: '93.184.216.34',
        ports: ports.map((port) => ({ port, state: 'open' as const, timingMs: 5 })),
      },
    },
  });
  const portOf = (finding: { evidence: Record<string, unknown> }): unknown =>
    finding.evidence['port'];

  it('downgrades a listed sensitive port to informational and marks it expected', () => {
    const findings = markExpectedPorts(evaluate(scanWithOpen([3306, 5432])), [3306]);
    const mysql = findings.find((f) => portOf(f) === 3306);
    const postgres = findings.find((f) => portOf(f) === 5432);

    expect(mysql?.severity).toBe('informational');
    expect(mysql?.evidence['expected']).toBe(true);
    expect(mysql?.description).toContain('marked as expected');
    expect(postgres?.severity).toBe('medium');
    expect(postgres?.evidence['expected']).toBeUndefined();
  });

  it('keeps the finding in the report instead of removing it', () => {
    const before = evaluate(scanWithOpen([3306]));

    expect(markExpectedPorts(before, [3306])).toHaveLength(before.length);
  });

  it('leaves an ordinary open port alone, even when it is listed', () => {
    const before = evaluate(scanWithOpen([22]));

    expect(markExpectedPorts(before, [22])).toEqual(before);
  });

  it('sorts again, because a lower severity changes the order', () => {
    const before = evaluate(scanWithOpen([21, 3306]));
    const after = markExpectedPorts(before, [3306]);

    expect(before.map(portOf)).toEqual([3306, 21]);
    expect(after.map(portOf)).toEqual([21, 3306]);
  });

  it('returns the findings unchanged when no ports are listed', () => {
    const before = evaluate(scanWithOpen([3306]));

    expect(markExpectedPorts(before, [])).toEqual(before);
  });

  it('does not change the findings it was given', () => {
    const before = evaluate(scanWithOpen([3306]));
    const snapshot = JSON.stringify(before);

    markExpectedPorts(before, [3306]);

    expect(JSON.stringify(before)).toBe(snapshot);
  });
});
