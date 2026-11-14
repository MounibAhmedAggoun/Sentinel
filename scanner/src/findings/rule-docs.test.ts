import { describe, expect, it } from 'vitest';
import { RULE_CATALOG, type CatalogEntry } from './catalog.js';
import { renderRuleIndex, renderRulePage } from './rule-docs.js';
import { RULE_DOC_CONTENT } from './rule-docs-content.js';

const KNOWN_IDS = new Set<string>(RULE_CATALOG.map((entry) => entry.id));

const entryFor = (id: string): CatalogEntry => {
  const entry = RULE_CATALOG.find((candidate) => candidate.id === id);
  if (entry === undefined) throw new Error(`no catalog entry for ${id}`);
  return entry;
};

describe('RULE_DOC_CONTENT', () => {
  it('only has content for real rule IDs', () => {
    for (const id of Object.keys(RULE_DOC_CONTENT)) {
      expect(KNOWN_IDS.has(id)).toBe(true);
    }
  });

  it('has text for every section that is always shown', () => {
    for (const content of Object.values(RULE_DOC_CONTENT)) {
      expect(content.why.trim()).not.toBe('');
      expect(content.falsePositives.trim()).not.toBe('');
    }
  });

  it('has non-empty fixes and https references', () => {
    for (const content of Object.values(RULE_DOC_CONTENT)) {
      for (const fix of content.fixes) {
        expect(fix.server.trim()).not.toBe('');
        expect(fix.snippet.trim()).not.toBe('');
      }
      for (const reference of content.references) {
        expect(reference.title.trim()).not.toBe('');
        expect(reference.url.startsWith('https://')).toBe(true);
      }
    }
  });

  it('never claims a vulnerability', () => {
    for (const content of Object.values(RULE_DOC_CONTENT)) {
      const all = [content.why, content.falsePositives, ...content.fixes.map((f) => f.snippet)];
      expect(all.join(' ').toLowerCase()).not.toContain('vulnerab');
    }
  });
});

describe('renderRulePage with the real content', () => {
  it('shows the ID, title, area and severity from the catalog', () => {
    const entry = entryFor('HTTP-001');
    const content = RULE_DOC_CONTENT['HTTP-001'];
    if (content === undefined) throw new Error('missing content');

    const page = renderRulePage(entry, content);

    expect(page).toContain(`# HTTP-001: ${entry.title}`);
    expect(page).toContain('- **Area:** http');
    expect(page).toContain('- **Severity:** low');
  });

  it('has a section for each part of the content', () => {
    const entry = entryFor('HTTP-002');
    const content = RULE_DOC_CONTENT['HTTP-002'];
    if (content === undefined) throw new Error('missing content');

    const page = renderRulePage(entry, content);

    for (const heading of [
      '## What is observed',
      '## Why it can matter',
      '## False positives',
      '## How to fix',
      '### nginx',
      '### Apache',
      '## References',
    ]) {
      expect(page).toContain(heading);
    }
  });

  it('leaves out the fix and reference sections when there are none', () => {
    const entry = entryFor('HTTP-001');
    const page = renderRulePage(entry, {
      why: 'w',
      falsePositives: 'f',
      fixes: [],
      references: [],
    });

    expect(page).not.toContain('## How to fix');
    expect(page).not.toContain('## References');
  });

  it('uses a longer code fence when a snippet contains backticks', () => {
    const entry = entryFor('HTTP-001');
    const page = renderRulePage(entry, {
      why: 'w',
      falsePositives: 'f',
      fixes: [{ server: 's', snippet: 'a\n```\nb' }],
      references: [],
    });

    expect(page).toContain('````');
  });

  it('writes angle brackets as text, not as HTML', () => {
    const page = renderRulePage(
      { ...entryFor('HTTP-001'), title: 'port <port> open' },
      { why: '<b>w</b>', falsePositives: 'f', fixes: [], references: [] },
    );

    expect(page).not.toContain('<port>');
    expect(page).not.toContain('<b>');
    expect(page).toContain('port &lt;port&gt; open');
  });
});

describe('renderRuleIndex', () => {
  it('lists only the documented rules, with a link to each page', () => {
    const index = renderRuleIndex(RULE_CATALOG, new Set(['HTTP-001', 'HTTP-002']));

    expect(index).toContain('[HTTP-001](HTTP-001.md)');
    expect(index).toContain('[HTTP-002](HTTP-002.md)');
    expect(index).not.toContain('HTTP-003');
  });
});
