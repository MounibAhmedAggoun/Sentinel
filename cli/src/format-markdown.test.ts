import { describe, expect, it } from 'vitest';
import type { Report } from '@sentinel/scanner';
import { formatMarkdown } from './format-markdown.js';

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

describe('formatMarkdown', () => {
  it('shows the target and timing, and says so when there are no findings', () => {
    const text = formatMarkdown(report());

    expect(text).toContain('# Sentinel scan of example\\.com');
    expect(text).toContain('took 2000 ms');
    expect(text).toContain('No findings were observed.');
    expect(text).not.toContain('Checks that did not complete');
  });

  it('counts findings by severity in the summary table', () => {
    const text = formatMarkdown(
      report({
        findings: [
          finding('high', 'X-1', 'one'),
          finding('low', 'X-2', 'two'),
          finding('low', 'X-3', 'three'),
        ],
      }),
    );

    expect(text).toContain('| high | 1 |');
    expect(text).toContain('| medium | 0 |');
    expect(text).toContain('| low | 2 |');
    expect(text).toContain('| informational | 0 |');
  });

  it('shows each finding with severity, rule, description, evidence and remediation', () => {
    const text = formatMarkdown(
      report({ findings: [finding('low', 'HTTP-001', 'Security header not observed')] }),
    );

    expect(text).toContain('### 1. Security header not observed');
    expect(text).toContain('- **Severity:** low');
    expect(text).toContain('- **Rule:** HTTP\\-001');
    expect(text).toContain('```json');
    expect(text).toContain('"a": 1');
    expect(text).toContain('**Remediation:** r');
  });

  it('lists checks that did not complete', () => {
    const text = formatMarkdown(
      report({
        errors: [
          {
            module: 'http',
            code: 'CONNECTION_FAILED',
            message: 'connect ECONNREFUSED 127.0.0.1:443',
          },
        ],
      }),
    );

    expect(text).toContain('## Checks that did not complete');
    expect(text).toContain(
      '- http: CONNECTION\\_FAILED (connect ECONNREFUSED 127\\.0\\.0\\.1:443)',
    );
  });
});

describe('formatMarkdown with hostile text from a scanned server', () => {
  it('escapes HTML tags in a title', () => {
    const text = formatMarkdown(
      report({ findings: [finding('low', 'X-1', '<script>alert(1)</script>')] }),
    );

    expect(text).not.toContain('<script>');
    expect(text).toContain('\\<script\\>');
  });

  it('escapes a Markdown link in a title', () => {
    const text = formatMarkdown(
      report({ findings: [finding('low', 'X-1', '[click](http://evil.example)')] }),
    );

    expect(text).not.toContain('[click](');
    expect(text).toContain('\\[click\\]\\(');
  });

  it('removes escape sequences and control characters', () => {
    const text = formatMarkdown(
      report({
        findings: [
          { ...finding('low', 'X-1', 'bad\u001b[31mred'), evidence: { value: 'a\u009bb' } },
        ],
      }),
    );

    expect(text.includes('\u001b')).toBe(false);
    expect(text.includes('\u009b')).toBe(false);
    expect(text).toContain('bad?');
  });

  it('uses a longer code fence when the evidence contains backticks', () => {
    const text = formatMarkdown(
      report({
        findings: [
          { ...finding('low', 'X-1', 't'), evidence: { value: 'x\n```\n# Injected heading' } },
        ],
      }),
    );
    const lines = text.split('\n');

    expect(text).toContain('````json');
    expect(lines.filter((line) => line === '````')).toHaveLength(1);
    expect(lines).not.toContain('# Injected heading');
  });
});
