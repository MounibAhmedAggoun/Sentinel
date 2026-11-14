import type { CatalogEntry } from '@sentinel/scanner';
import { sanitize } from './format.js';

const MAX_TITLE = 70;

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 3)}...` : text;
}

function pad(text: string, width: number): string {
  return text.padEnd(width, ' ');
}

/** Turns the rule catalog into a table. Pure: it returns text and prints nothing. */
export function formatRuleList(catalog: readonly CatalogEntry[]): string {
  const rows = catalog.map((entry) => ({
    id: sanitize(entry.id),
    severity: entry.severities.join('/').toUpperCase(),
    title: truncate(sanitize(entry.title), MAX_TITLE),
  }));

  const idWidth = Math.max('RULE'.length, ...rows.map((row) => row.id.length));
  const severityWidth = Math.max('SEVERITY'.length, ...rows.map((row) => row.severity.length));

  const lines: string[] = [];
  lines.push(`${pad('RULE', idWidth)}  ${pad('SEVERITY', severityWidth)}  FINDING`);
  lines.push(`${'-'.repeat(idWidth)}  ${'-'.repeat(severityWidth)}  ${'-'.repeat(MAX_TITLE)}`);
  for (const row of rows) {
    lines.push(`${pad(row.id, idWidth)}  ${pad(row.severity, severityWidth)}  ${row.title}`);
  }
  lines.push('', `${rows.length} rules`, '');

  return lines.join('\n');
}
