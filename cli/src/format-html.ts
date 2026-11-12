import type { Report } from '@sentinel/scanner';
import { sanitize } from './format.js';

const SEVERITIES = ['high', 'medium', 'low', 'informational'] as const;

/** Escapes the characters that matter in HTML text and attribute values. */
function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Report text can come from the scanned server: remove control characters, then escape. */
function h(text: string): string {
  return escapeHtml(sanitize(text));
}

/**
 * Pretty JSON for the evidence block. JSON.stringify already escapes control
 * characters inside strings, so only the C1 range needs removing here, and the
 * newlines that give the JSON its layout are kept.
 */
function evidenceJson(evidence: Record<string, unknown>): string {
  return escapeHtml(JSON.stringify(evidence, null, 2).replace(/[\u007f-\u009f]/g, '?'));
}

const STYLE = `
:root {
  color-scheme: light dark;
  --bg: #ffffff;
  --fg: #1a1a1a;
  --muted: #5c5c5c;
  --border: #d8d8d8;
  --card: #f6f6f6;
  --high: #b3261e;
  --medium: #b45309;
  --low: #8a6d00;
  --informational: #1d5fa8;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14161a;
    --fg: #e8e8e8;
    --muted: #a0a0a0;
    --border: #33363c;
    --card: #1c1f24;
    --high: #ff8a80;
    --medium: #ffb454;
    --low: #e6c85c;
    --informational: #7db7f0;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0 auto;
  max-width: 60rem;
  padding: 2rem 1rem;
  background: var(--bg);
  color: var(--fg);
  font: 16px/1.5 system-ui, sans-serif;
}
h1 { margin: 0 0 0.25rem; font-size: 1.6rem; }
h2 { margin-top: 2rem; font-size: 1.2rem; }
.meta { color: var(--muted); margin: 0 0 1.5rem; }
.summary { display: flex; flex-wrap: wrap; gap: 0.75rem; padding: 0; list-style: none; }
.summary li {
  border: 1px solid var(--border);
  border-radius: 0.5rem;
  padding: 0.5rem 1rem;
  background: var(--card);
}
.summary strong { display: block; font-size: 1.4rem; }
.finding {
  border: 1px solid var(--border);
  border-left-width: 0.4rem;
  border-radius: 0.5rem;
  padding: 0.75rem 1rem;
  margin: 1rem 0;
  background: var(--card);
}
.finding h3 { margin: 0 0 0.25rem; font-size: 1.05rem; }
.finding .tags { color: var(--muted); font-size: 0.9rem; margin: 0 0 0.5rem; }
.sev-high { border-left-color: var(--high); }
.sev-medium { border-left-color: var(--medium); }
.sev-low { border-left-color: var(--low); }
.sev-informational { border-left-color: var(--informational); }
pre {
  overflow-x: auto;
  margin: 0.5rem 0;
  padding: 0.75rem;
  border: 1px solid var(--border);
  border-radius: 0.4rem;
  background: var(--bg);
  font: 0.85rem/1.4 ui-monospace, monospace;
}
`;

/**
 * Turns a report into one self-contained HTML page: no scripts, no external
 * files. The page also carries a Content-Security-Policy that forbids both, as a
 * second layer in case text from the scanned server ever slipped past escaping.
 * Pure: it returns text and prints nothing.
 */
export function formatHtml(report: Report): string {
  const parts: string[] = [];

  parts.push(
    '<!doctype html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">`,
    `<title>Sentinel scan of ${h(report.target)}</title>`,
    `<style>${STYLE}</style>`,
    '</head>',
    '<body>',
    `<h1>Sentinel scan of ${h(report.target)}</h1>`,
    `<p class="meta">Started ${h(report.startedAt)}, took ${report.durationMs} ms. Sentinel ${h(report.tool.version)}.</p>`,
  );

  parts.push('<h2>Summary</h2>', '<ul class="summary">');
  for (const severity of SEVERITIES) {
    const count = report.findings.filter((f) => f.severity === severity).length;
    parts.push(`<li><strong>${count}</strong>${severity}</li>`);
  }
  parts.push('</ul>');

  parts.push('<h2>Findings</h2>');
  if (report.findings.length === 0) {
    parts.push('<p>No findings were observed.</p>');
  }
  report.findings.forEach((finding, index) => {
    parts.push(
      `<section class="finding sev-${finding.severity}">`,
      `<h3>${index + 1}. ${h(finding.title)}</h3>`,
      `<p class="tags">Severity: ${finding.severity} &middot; Rule: ${h(finding.ruleId)}</p>`,
      `<p>${h(finding.description)}</p>`,
      '<p><strong>Evidence</strong></p>',
      `<pre>${evidenceJson(finding.evidence)}</pre>`,
      `<p><strong>Remediation:</strong> ${h(finding.remediation)}</p>`,
      '</section>',
    );
  });

  if (report.errors.length > 0) {
    parts.push('<h2>Checks that did not complete</h2>', '<ul>');
    for (const error of report.errors) {
      parts.push(`<li>${h(error.module)}: ${h(error.code)} (${h(error.message)})</li>`);
    }
    parts.push('</ul>');
  }

  parts.push('</body>', '</html>', '');
  return parts.join('\n');
}
