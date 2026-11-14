import { describe, expect, it } from 'vitest';
import { RULE_CATALOG } from '@sentinel/scanner';
import { filterFindings, parseRuleList } from './rule-filter.js';

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
