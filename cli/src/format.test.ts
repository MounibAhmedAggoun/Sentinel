import { describe, expect, it } from 'vitest';
import type { Report } from '@sentinel/scanner';
import { formatTerminal, sanitize } from './format.js';

function report(overrides: Partial<Report> = {}): Report {
  return {
    schemaVersion: '1.0',
    tool: { name: 'sentinel', version: '0.1.0' },
    target: 'example.com',
    startedAt: '2026-10-01T10:00:00.000Z',
    finishedAt: '2026-10-01T10:00:02.000Z',
    durationMs: 2000,
    findings: [],
    errors: [],
    ...overrides,
  } as Report;
}

const finding = (
  severity: Report['findings'][number]['severity'],
  ruleId: string,
  title: string,
): Report['findings'][number] => ({
  ruleId,
  title,
  severity,
  description: 'd',
  evidence: { a: 1 },
  remediation: 'r',
});

describe('formatTerminal', () => {
  it('shows the target, timing and a zero count when there are no findings', () => {
    const text = formatTerminal(report());

    expect(text).toContain('Sentinel scan of example.com');
    expect(text).toContain('took 2000 ms');
    expect(text).toContain('Findings: 0 (0 high, 0 medium, 0 low, 0 informational)');
    expect(text).not.toContain('SEVERITY');
  });

  it('lists findings in a table with severity, rule and title', () => {
    const text = formatTerminal(
      report({
        findings: [
          finding('high', 'TLS-001', 'Certificate expiry date has passed'),
          finding('informational', 'TCP-001', 'TCP port 80 observed open'),
        ],
      }),
    );

    expect(text).toContain('Findings: 2 (1 high, 0 medium, 0 low, 1 informational)');
    expect(text).toMatch(/HIGH\s+TLS-001\s+Certificate expiry date has passed/);
    expect(text).toMatch(/INFORMATIONAL\s+TCP-001\s+TCP port 80 observed open/);
  });

  it('truncates very long titles', () => {
    const text = formatTerminal(
      report({ findings: [finding('low', 'HTTP-001', 'x'.repeat(500))] }),
    );

    expect(text).toContain('...');
    expect(text.split('\n').every((line) => line.length < 200)).toBe(true);
  });

  it('lists checks that did not complete', () => {
    const text = formatTerminal(
      report({
        errors: [{ module: 'tls', code: 'TIMEOUT', message: 'no response within 5000ms' }],
      }),
    );

    expect(text).toContain('Checks that did not complete:');
    expect(text).toContain('tls: TIMEOUT (no response within 5000ms)');
  });

  it('omits the errors section when every check worked', () => {
    expect(formatTerminal(report())).not.toContain('did not complete');
  });

  it('strips terminal escape sequences from text a target controls', () => {
    const hostile = 'Server \u001b[31mRED\u001b[0m \u0007bell';
    const text = formatTerminal(report({ findings: [finding('low', 'HTTP-006', hostile)] }));

    expect(text).not.toContain('\u001b');
    expect(text).not.toContain('\u0007');
  });
});

describe('sanitize', () => {
  it('replaces control characters', () => {
    expect(sanitize('a\u001bb\u0000c\u007fd')).toBe('a?b?c?d');
  });

  it('keeps normal text, spaces and unicode', () => {
    expect(sanitize('Hello, wörld 你好')).toBe('Hello, wörld 你好');
  });

  it('replaces newlines so one value cannot fake extra lines', () => {
    expect(sanitize('line one\nline two')).toBe('line one?line two');
  });
});
