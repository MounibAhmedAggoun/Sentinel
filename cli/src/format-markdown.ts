import type { Report } from '@sentinel/scanner';
import { sanitize } from './format.js';

const SEVERITIES = ['high', 'medium', 'low', 'informational'] as const;

/**
 * Escapes text so Markdown shows it literally. Report text can come from the
 * scanned server, so control characters are removed and Markdown and HTML
 * characters are escaped.
 */
function md(text: string): string {
  return sanitize(text).replace(/[\\`*_{}[\]()#+.!|<>~&-]/g, '\\$&');
}

/** Pretty JSON for the evidence block, with C1 control characters removed. */
function evidenceJson(evidence: Record<string, unknown>): string {
  return JSON.stringify(evidence, null, 2).replace(/[\u007f-\u009f]/g, '?');
}

/** A code block whose fence is longer than any run of backticks inside it. */
function fenced(text: string): string {
  const longest = Math.max(0, ...(text.match(/`+/g) ?? []).map((run) => run.length));
  const fence = '`'.repeat(Math.max(3, longest + 1));
  return `${fence}json\n${text}\n${fence}`;
}

/** Turns a report into a Markdown document. Pure: it returns text and prints nothing. */
export function formatMarkdown(report: Report): string {
  const lines: string[] = [];

  lines.push(`# Sentinel scan of ${md(report.target)}`, '');
  lines.push(
    `Started ${md(report.startedAt)}, took ${report.durationMs} ms. Sentinel ${md(report.tool.version)}.`,
    '',
  );

  lines.push('## Summary', '', '| Severity | Findings |', '| --- | --- |');
  for (const severity of SEVERITIES) {
    const count = report.findings.filter((f) => f.severity === severity).length;
    lines.push(`| ${severity} | ${count} |`);
  }
  lines.push('');

  lines.push('## Findings', '');
  if (report.findings.length === 0) {
    lines.push('No findings were observed.', '');
  }
  report.findings.forEach((finding, index) => {
    lines.push(`### ${index + 1}. ${md(finding.title)}`, '');
    lines.push(`- **Severity:** ${finding.severity}`, `- **Rule:** ${md(finding.ruleId)}`, '');
    lines.push(md(finding.description), '');
    lines.push('**Evidence**', '', fenced(evidenceJson(finding.evidence)), '');
    lines.push(`**Remediation:** ${md(finding.remediation)}`, '');
  });

  if (report.errors.length > 0) {
    lines.push('## Checks that did not complete', '');
    for (const error of report.errors) {
      lines.push(`- ${md(error.module)}: ${md(error.code)} (${md(error.message)})`);
    }
    lines.push('');
  }

  return lines.join('\n');
}
