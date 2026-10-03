import { describe, expect, it } from 'vitest';
import { parseDmarc, parseSpf } from './parsers.js';

describe('parseSpf', () => {
  it.each([
    ['v=spf1 include:_spf.google.com -all', '-all'],
    ['v=spf1 include:_spf.google.com ~all', '~all'],
    ['v=spf1 ?all', '?all'],
    ['v=spf1 +all', '+all'],
    ['v=spf1 all', '+all'],
    ['V=SPF1 -ALL', '-all'],
  ])('parses %j', (raw, all) => {
    expect(parseSpf(['unrelated', raw])).toEqual({ raw, all });
  });

  it('returns all: null when the record has no "all" mechanism', () => {
    expect(parseSpf(['v=spf1 include:example.com'])?.all).toBeNull();
  });

  it('returns null when there is no SPF record', () => {
    expect(parseSpf(['google-site-verification=abc', 'hello'])).toBeNull();
    expect(parseSpf([])).toBeNull();
  });

  it('does not match records that merely mention spf1', () => {
    expect(parseSpf(['not v=spf1 -all'])).toBeNull();
  });
});

describe('parseDmarc', () => {
  it.each([
    ['v=DMARC1; p=none; rua=mailto:a@example.com', 'none'],
    ['v=DMARC1; p=quarantine', 'quarantine'],
    ['v=DMARC1; p=reject; pct=100', 'reject'],
    ['v=DMARC1;p=REJECT;', 'reject'],
  ])('parses %j', (raw, policy) => {
    expect(parseDmarc([raw])).toEqual({ raw, policy });
  });

  it('returns policy: null when p= is missing or invalid', () => {
    expect(parseDmarc(['v=DMARC1; rua=mailto:a@example.com'])?.policy).toBeNull();
    expect(parseDmarc(['v=DMARC1; p=bogus'])?.policy).toBeNull();
  });

  it('does not mistake sp= for p=', () => {
    expect(parseDmarc(['v=DMARC1; sp=reject'])?.policy).toBeNull();
  });

  it('returns null when there is no DMARC record', () => {
    expect(parseDmarc(['v=spf1 -all'])).toBeNull();
    expect(parseDmarc([])).toBeNull();
  });
});
