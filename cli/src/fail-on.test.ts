import { describe, expect, it } from 'vitest';
import {
  DEFAULT_FAIL_ON,
  hasFindingsAtOrAbove,
  parseFailOn,
  SEVERITY_ORDER,
  type Severity,
} from './fail-on.js';

const at = (...severities: Severity[]): { severity: Severity }[] =>
  severities.map((severity) => ({ severity }));

describe('parseFailOn', () => {
  it.each(SEVERITY_ORDER)('accepts %s', (name) => {
    expect(parseFailOn(name)).toEqual({ ok: true, severity: name });
  });

  it.each(['', 'critical', 'HIGH', 'High', ' low', 'low ', 'info', 'none'])('rejects %j', (raw) => {
    expect(parseFailOn(raw).ok).toBe(false);
  });

  it('names the valid severities in the error', () => {
    const result = parseFailOn('nope');

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe('fail-on must be one of: informational, low, medium, high');
    }
  });
});

describe('hasFindingsAtOrAbove', () => {
  it("keeps today's default: informational alone does not fail, low does", () => {
    expect(DEFAULT_FAIL_ON).toBe('low');
    expect(hasFindingsAtOrAbove(at('informational'), DEFAULT_FAIL_ON)).toBe(false);
    expect(hasFindingsAtOrAbove(at('informational', 'low'), DEFAULT_FAIL_ON)).toBe(true);
  });

  it('is false when there are no findings, whatever the threshold', () => {
    for (const threshold of SEVERITY_ORDER) {
      expect(hasFindingsAtOrAbove([], threshold)).toBe(false);
    }
  });

  it('with high, ignores everything below high', () => {
    expect(hasFindingsAtOrAbove(at('informational', 'low', 'medium'), 'high')).toBe(false);
    expect(hasFindingsAtOrAbove(at('low', 'high'), 'high')).toBe(true);
  });

  it('with medium, fails on medium and high but not on low', () => {
    expect(hasFindingsAtOrAbove(at('low'), 'medium')).toBe(false);
    expect(hasFindingsAtOrAbove(at('medium'), 'medium')).toBe(true);
    expect(hasFindingsAtOrAbove(at('high'), 'medium')).toBe(true);
  });

  it('with informational, fails on any finding at all', () => {
    expect(hasFindingsAtOrAbove(at('informational'), 'informational')).toBe(true);
  });
});
