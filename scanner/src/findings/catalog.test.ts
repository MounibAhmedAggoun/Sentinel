import { describe, expect, it } from 'vitest';
import { RULE_CATALOG } from './catalog.js';
import { scanWithHeaders } from './fixtures.js';
import { RULE_IDS } from './ids.js';
import { headerRules } from './rules/headers.js';

const SEVERITY_ORDER = ['informational', 'low', 'medium', 'high'];

describe('RULE_CATALOG', () => {
  it('has an entry for every rule ID', () => {
    const catalogIds = RULE_CATALOG.map((entry) => entry.id).sort();

    expect(catalogIds).toEqual(Object.values(RULE_IDS).sort());
  });

  it('has no repeated IDs', () => {
    const ids = RULE_CATALOG.map((entry) => entry.id);

    expect(new Set(ids).size).toBe(ids.length);
  });

  it('uses an area that matches the ID prefix', () => {
    for (const entry of RULE_CATALOG) {
      expect(entry.id.split('-')[0]?.toLowerCase()).toBe(entry.area);
    }
  });

  it('lists severities lowest first, with no repeats', () => {
    for (const entry of RULE_CATALOG) {
      const positions = entry.severities.map((severity) => SEVERITY_ORDER.indexOf(severity));

      expect(entry.severities.length).toBeGreaterThan(0);
      expect(positions.every((position) => position >= 0)).toBe(true);
      expect(positions).toEqual([...positions].sort((a, b) => a - b));
      expect(new Set(positions).size).toBe(positions.length);
    }
  });

  it('has a title and a summary for every entry', () => {
    for (const entry of RULE_CATALOG) {
      expect(entry.title.trim()).not.toBe('');
      expect(entry.summary.trim()).not.toBe('');
    }
  });

  it('never claims a vulnerability', () => {
    for (const entry of RULE_CATALOG) {
      expect(`${entry.title} ${entry.summary}`.toLowerCase()).not.toContain('vulnerab');
    }
  });

  it('matches the real finding titles and severities of the header rules', () => {
    const findings = headerRules(scanWithHeaders({}));

    expect(findings.length).toBeGreaterThan(0);
    for (const finding of findings) {
      const entry = RULE_CATALOG.find((candidate) => candidate.id === finding.ruleId);

      expect(entry?.title).toBe(finding.title);
      expect(entry?.severities).toContain(finding.severity);
    }
  });
});
