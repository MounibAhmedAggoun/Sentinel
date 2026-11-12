import { describe, expect, it } from 'vitest';
import type { Report } from '@sentinel/scanner';
import { formatHtml } from './format-html.js';

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

describe('formatHtml', () => {
  it('produces a complete page with the target in the title and heading', () => {
    const html = formatHtml(report());

    expect(html.startsWith('<!doctype html>')).toBe(true);
    expect(html).toContain('<title>Sentinel scan of example.com</title>');
    expect(html).toContain('<h1>Sentinel scan of example.com</h1>');
    expect(html).toContain('took 2000 ms');
    expect(html).toContain('No findings were observed.');
    expect(html).not.toContain('Checks that did not complete');
  });

  it('is self-contained: no scripts and no external files', () => {
    const html = formatHtml(report({ findings: [finding('low', 'X-1', 't')] }));

    expect(html).not.toContain('<script');
    expect(html).not.toContain('<link');
    expect(html).not.toContain('<img');
    expect(html).not.toMatch(/(src|href)=/);
    expect(html).toContain(`content="default-src 'none'; style-src 'unsafe-inline'"`);
  });

  it('counts findings by severity in the summary', () => {
    const html = formatHtml(
      report({
        findings: [
          finding('high', 'X-1', 'one'),
          finding('low', 'X-2', 'two'),
          finding('low', 'X-3', 'three'),
        ],
      }),
    );

    expect(html).toContain('<li><strong>1</strong>high</li>');
    expect(html).toContain('<li><strong>0</strong>medium</li>');
    expect(html).toContain('<li><strong>2</strong>low</li>');
    expect(html).toContain('<li><strong>0</strong>informational</li>');
  });

  it('shows each finding with severity class, rule, description, evidence and remediation', () => {
    const html = formatHtml(
      report({ findings: [finding('medium', 'HTTP-001', 'Security header not observed')] }),
    );

    expect(html).toContain('<section class="finding sev-medium">');
    expect(html).toContain('<h3>1. Security header not observed</h3>');
    expect(html).toContain('Severity: medium');
    expect(html).toContain('Rule: HTTP-001');
    expect(html).toContain('<pre>{\n  &quot;a&quot;: 1\n}</pre>');
    expect(html).toContain('<strong>Remediation:</strong> r');
  });

  it('lists checks that did not complete', () => {
    const html = formatHtml(
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

    expect(html).toContain('<h2>Checks that did not complete</h2>');
    expect(html).toContain('<li>http: CONNECTION_FAILED (connect ECONNREFUSED 127.0.0.1:443)</li>');
  });
});

describe('formatHtml with hostile text from a scanned server', () => {
  it('escapes a script tag in a title', () => {
    const html = formatHtml(
      report({ findings: [finding('low', 'X-1', '<script>alert(1)</script>')] }),
    );

    expect(html).not.toContain('<script');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  it('escapes quotes and tags in the target, which also appears in the title', () => {
    const html = formatHtml(report({ target: '"><img src=x onerror=alert(1)>' }));

    expect(html).not.toContain('<img');
    expect(html).toContain('&quot;&gt;&lt;img src=x onerror=alert(1)&gt;');
  });

  it('escapes tags inside the evidence block', () => {
    const html = formatHtml(
      report({
        findings: [
          { ...finding('low', 'X-1', 't'), evidence: { value: '</pre><script>x</script>' } },
        ],
      }),
    );

    expect(html).not.toContain('<script');
    expect(html).not.toContain('</pre><');
    expect(html).toContain('&lt;/pre&gt;&lt;script&gt;x&lt;/script&gt;');
  });

  it('removes escape sequences and control characters', () => {
    const html = formatHtml(
      report({
        findings: [
          { ...finding('low', 'X-1', 'bad\u001b[31mred'), evidence: { value: 'a\u009bb' } },
        ],
      }),
    );

    expect(html.includes('\u001b')).toBe(false);
    expect(html.includes('\u009b')).toBe(false);
    expect(html).toContain('bad?');
  });
});
