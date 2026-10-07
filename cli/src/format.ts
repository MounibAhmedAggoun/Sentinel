import type { Report } from '@sentinel/scanner';

const SEVERITIES = ['high', 'medium', 'low', 'informational'] as const;
const MAX_TITLE = 80;

/**
 * Removes control characters, including the ESC that starts terminal escape
 * sequences. Report text can come from the target (for example a header value),
 * and printing it raw could let a hostile server rewrite what the terminal shows.
 */
export function sanitize(text: string): string {
  let result = '';
  for (const char of text) {
    const code = char.codePointAt(0) ?? 0;
    const isControl = code <= 0x1f || (code >= 0x7f && code <= 0x9f);
    result += isControl ? '?' : char;
  }
  return result;
}

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 3)}...` : text;
}

function pad(text: string, width: number): string {
  return text.padEnd(width, ' ');
}

/** Turns a report into a readable terminal summary. Pure: it returns text and prints nothing. */
export function formatTerminal(report: Report): string {
  const lines: string[] = [];

  lines.push(`Sentinel scan of ${sanitize(report.target)}`);
  lines.push(`Started ${report.startedAt}, took ${report.durationMs} ms`);
  lines.push('');

  const counts = SEVERITIES.map(
    (severity) => `${report.findings.filter((f) => f.severity === severity).length} ${severity}`,
  );
  lines.push(`Findings: ${report.findings.length} (${counts.join(', ')})`);
  lines.push('');

  if (report.findings.length > 0) {
    const rows = report.findings.map((f) => ({
      severity: f.severity.toUpperCase(),
      rule: sanitize(f.ruleId),
      title: truncate(sanitize(f.title), MAX_TITLE),
    }));
    const severityWidth = Math.max('SEVERITY'.length, ...rows.map((r) => r.severity.length));
    const ruleWidth = Math.max('RULE'.length, ...rows.map((r) => r.rule.length));

    lines.push(`${pad('SEVERITY', severityWidth)}  ${pad('RULE', ruleWidth)}  FINDING`);
    lines.push(`${'-'.repeat(severityWidth)}  ${'-'.repeat(ruleWidth)}  ${'-'.repeat(MAX_TITLE)}`);
    for (const row of rows) {
      lines.push(`${pad(row.severity, severityWidth)}  ${pad(row.rule, ruleWidth)}  ${row.title}`);
    }
    lines.push('');
  }

  if (report.errors.length > 0) {
    lines.push('Checks that did not complete:');
    for (const error of report.errors) {
      lines.push(
        `  ${sanitize(error.module)}: ${sanitize(error.code)} (${truncate(sanitize(error.message), MAX_TITLE)})`,
      );
    }
    lines.push('');
  }

  return lines.join('\n');
}
