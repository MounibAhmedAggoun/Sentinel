import { describe, expect, it } from 'vitest';
import { RULE_CATALOG, type CatalogEntry } from '@sentinel/scanner';
import { formatRuleList } from './format-rules.js';

describe('formatRuleList with the real catalog', () => {
  it('lists every rule', () => {
    const text = formatRuleList(RULE_CATALOG);

    for (const entry of RULE_CATALOG) {
      expect(text).toContain(entry.id);
    }
    expect(text).toContain(`${RULE_CATALOG.length} rules`);
  });

  it('has a header row and a divider', () => {
    const lines = formatRuleList(RULE_CATALOG).split('\n');

    expect(lines[0]).toMatch(/^RULE\s+SEVERITY\s+FINDING$/);
    expect(lines[1]).toMatch(/^-+\s+-+\s+-+$/);
  });

  it('shows every severity a rule can report', () => {
    const text = formatRuleList(RULE_CATALOG);

    expect(text).toMatch(/TLS-002\s+LOW\/MEDIUM\/HIGH/);
    expect(text).toMatch(/TCP-002\s+LOW\/MEDIUM/);
  });

  it('keeps every row to a bounded width', () => {
    for (const line of formatRuleList(RULE_CATALOG).split('\n')) {
      expect(line.length).toBeLessThanOrEqual(110);
    }
  });
});

describe('formatRuleList with hostile text', () => {
  it('removes control characters from IDs and titles', () => {
    const hostile = {
      id: 'X-1\u001b[31m',
      area: 'http',
      title: 'bad\u001b[31mred',
      severities: ['low'],
      summary: 's',
    } as unknown as CatalogEntry;
    const text = formatRuleList([hostile]);

    expect(text.includes('\u001b')).toBe(false);
    expect(text).toContain('bad?');
  });

  it('prints just the header for an empty catalog', () => {
    const text = formatRuleList([]);

    expect(text).toContain('0 rules');
    expect(text).toMatch(/^RULE\s+SEVERITY\s+FINDING/);
  });
});
