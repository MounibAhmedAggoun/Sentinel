import type { Report } from '@sentinel/scanner';
import { sanitize } from './format.js';

const RANK: Record<string, number> = { informational: 0, low: 1, medium: 2, high: 3 };

/** Escapes text for XML. Control characters are removed first: XML 1.0 cannot hold them. */
function xml(text: string): string {
  return sanitize(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Turns a report into a JUnit XML document. Pure: it returns text and prints nothing.
 * A finding at or above failOn is a failure, so the result agrees with the exit code.
 */
export function formatJunit(report: Report, failOn: string): string {
  const threshold = RANK[failOn] ?? RANK['high'] ?? 3;
  const seconds = (report.durationMs / 1000).toFixed(3);

  const cases: string[] = [];
  let failures = 0;

  for (const finding of report.findings) {
    const name = xml(`${finding.ruleId}: ${finding.title}`);
    const className = xml(finding.ruleId.split('-')[0] ?? 'RULE');
    const body = xml(
      `${finding.description} Evidence: ${JSON.stringify(finding.evidence)} Remediation: ${finding.remediation}`,
    );
    if ((RANK[finding.severity] ?? 0) >= threshold) {
      failures++;
      cases.push(
        `    <testcase classname="${className}" name="${name}">\n` +
          `      <failure type="${xml(finding.severity)}" message="${xml(finding.title)}">${body}</failure>\n` +
          `    </testcase>`,
      );
    } else {
      cases.push(
        `    <testcase classname="${className}" name="${name}">\n` +
          `      <system-out>${xml(finding.severity)}: ${body}</system-out>\n` +
          `    </testcase>`,
      );
    }
  }

  for (const error of report.errors) {
    cases.push(
      `    <testcase classname="scan" name="${xml(`${error.module}: ${error.code}`)}">\n` +
        `      <error type="${xml(error.code)}" message="${xml(error.message)}"/>\n` +
        `    </testcase>`,
    );
  }

  const tests = report.findings.length + report.errors.length;
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<testsuites>',
    `  <testsuite name="${xml(`Sentinel scan of ${report.target}`)}" tests="${tests}" failures="${failures}" errors="${report.errors.length}" time="${seconds}" timestamp="${xml(report.startedAt)}">`,
    ...cases,
    '  </testsuite>',
    '</testsuites>',
    '',
  ].join('\n');
}
