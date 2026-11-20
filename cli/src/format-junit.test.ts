import { describe, expect, it } from 'vitest';
import type { Report } from '@sentinel/scanner';
import { formatJunit } from './format-junit.js';

function report(overrides: Partial<Report> = {}): Report {
  return {
    schemaVersion: '1.1',
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

describe('formatJunit', () => {
  it('writes an XML declaration and one suite named after the target', () => {
    const text = formatJunit(report(), 'low');

    expect(text.startsWith('<?xml version="1.0" encoding="UTF-8"?>')).toBe(true);
    expect(text).toContain('<testsuite name="Sentinel scan of example.com"');
    expect(text).toContain('tests="0" failures="0" errors="0" time="2.000"');
  });

  it('makes a failure for a finding at or above the threshold', () => {
    const text = formatJunit(
      report({ findings: [finding('medium', 'TLS-003', 'Self-signed')] }),
      'medium',
    );

    expect(text).toContain('<failure type="medium"');
    expect(text).toContain('failures="1"');
    expect(text).toContain('name="TLS-003: Self-signed"');
    expect(text).toContain('classname="TLS"');
  });

  it('passes a finding below the threshold and keeps its text in system-out', () => {
    const text = formatJunit(report({ findings: [finding('low', 'HTTP-001', 'No CSP')] }), 'high');

    expect(text).not.toContain('<failure');
    expect(text).toContain('failures="0"');
    expect(text).toContain('<system-out>low:');
  });

  it('counts the threshold itself as a failure, one level below as a pass', () => {
    const findings = [finding('low', 'HTTP-001', 'a'), finding('informational', 'TCP-001', 'b')];
    const text = formatJunit(report({ findings }), 'low');

    expect(text).toContain('failures="1"');
  });

  it('reports a failed check as an error case', () => {
    const errors = [{ module: 'tls', code: 'TIMEOUT', message: 'slow' }];
    const text = formatJunit(report({ errors }), 'high');

    expect(text).toContain('<error type="TIMEOUT" message="slow"/>');
    expect(text).toContain('tests="1"');
    expect(text).toContain('errors="1"');
  });

  it('escapes XML characters from the target and removes control characters', () => {
    const hostile = finding('low', 'HTTP-006', 'x"><script>&');
    const withEvidence = { ...hostile, evidence: { value: '<b>\u0000\u001b[31m</b>' } };
    const text = formatJunit(report({ findings: [withEvidence] }), 'high');

    expect(text).not.toContain('<script>');
    expect(text).not.toContain('<b>');
    expect(text).not.toContain('\u0000');
    expect(text).not.toContain('\u001b');
    expect(text).toContain('&lt;script&gt;');
  });

  it('is deterministic for the same input', () => {
    const r = report({ findings: [finding('high', 'TLS-001', 't')] });

    expect(formatJunit(r, 'low')).toBe(formatJunit(r, 'low'));
  });
});
