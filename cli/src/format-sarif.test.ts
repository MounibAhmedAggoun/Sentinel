import { describe, expect, it } from 'vitest';
import type { Report } from '@sentinel/scanner';
import { formatSarif } from './format-sarif.js';

function report(overrides: Partial<Report> = {}): Report {
  return {
    schemaVersion: '1.1',
    tool: { name: 'sentinel', version: '0.2.0' },
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

const parse = (text: string) =>
  JSON.parse(text) as {
    version: string;
    runs: {
      tool: { driver: { name: string; version: string; rules: { id: string }[] } };
      invocations: { executionSuccessful: boolean; toolExecutionNotifications: unknown[] }[];
      results: {
        ruleId: string;
        level: string;
        locations: { physicalLocation: { artifactLocation: { uri: string } } }[];
      }[];
    }[];
  };

describe('formatSarif', () => {
  it('writes valid JSON with SARIF version 2.1.0 and the tool name and version', () => {
    const sarif = parse(formatSarif(report()));

    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]?.tool.driver.name).toBe('Sentinel');
    expect(sarif.runs[0]?.tool.driver.version).toBe('0.2.0');
    expect(sarif.runs[0]?.results).toEqual([]);
  });

  it('maps severities to SARIF levels', () => {
    const findings = [
      finding('high', 'TLS-001', 'a'),
      finding('medium', 'TLS-003', 'b'),
      finding('low', 'HTTP-001', 'c'),
      finding('informational', 'TCP-001', 'd'),
    ];
    const levels = parse(formatSarif(report({ findings }))).runs[0]?.results.map((r) => r.level);

    expect(levels).toEqual(['error', 'error', 'warning', 'note']);
  });

  it('points every result at the scanned target', () => {
    const results = parse(formatSarif(report({ findings: [finding('low', 'HTTP-001', 'a')] })))
      .runs[0]?.results;

    expect(results?.[0]?.locations[0]?.physicalLocation.artifactLocation.uri).toBe(
      'https://example.com/',
    );
  });

  it('lists each rule once, even when several findings share it', () => {
    const findings = [
      finding('informational', 'TCP-001', 'a'),
      finding('informational', 'TCP-001', 'b'),
    ];
    const rules = parse(formatSarif(report({ findings }))).runs[0]?.tool.driver.rules;

    expect(rules?.map((r) => r.id)).toEqual(['TCP-001']);
  });

  it('marks the run unsuccessful and lists a failed check as a notification', () => {
    const errors = [{ module: 'tls', code: 'TIMEOUT', message: 'slow' }];
    const invocation = parse(formatSarif(report({ errors }))).runs[0]?.invocations[0];

    expect(invocation?.executionSuccessful).toBe(false);
    expect(invocation?.toolExecutionNotifications).toHaveLength(1);
  });

  it('marks the run successful when every check completed', () => {
    const invocation = parse(formatSarif(report())).runs[0]?.invocations[0];

    expect(invocation?.executionSuccessful).toBe(true);
  });

  it('never writes raw control characters', () => {
    const hostile = {
      ...finding('low', 'HTTP-006', 'x\u001b[31m'),
      evidence: { v: '\u0000\u001b' },
    };
    const text = formatSarif(report({ findings: [hostile] }));

    expect(text).not.toContain('\u001b');
    expect(text).not.toContain('\u0000');
  });

  it('is deterministic for the same input', () => {
    const r = report({ findings: [finding('high', 'TLS-001', 't')] });

    expect(formatSarif(r)).toBe(formatSarif(r));
  });
});
