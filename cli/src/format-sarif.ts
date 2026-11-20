import { RULE_CATALOG, type Report } from '@sentinel/scanner';
import { sanitize } from './format.js';

const LEVEL: Record<string, 'error' | 'warning' | 'note'> = {
  high: 'error',
  medium: 'error',
  low: 'warning',
  informational: 'note',
};

/** Turns a report into SARIF 2.1.0. Pure: it returns text and prints nothing. */
export function formatSarif(report: Report): string {
  const uri = `https://${report.target}/`;

  const ruleIds = [...new Set(report.findings.map((f) => f.ruleId))];
  const rules = ruleIds.map((id) => {
    const entry = RULE_CATALOG.find((candidate) => candidate.id === id);
    return {
      id,
      shortDescription: { text: sanitize(entry?.title ?? id) },
      ...(entry !== undefined ? { fullDescription: { text: sanitize(entry.summary) } } : {}),
    };
  });

  const results = report.findings.map((finding) => ({
    ruleId: finding.ruleId,
    level: LEVEL[finding.severity] ?? 'note',
    message: {
      text: sanitize(`${finding.title}. ${finding.description} ${finding.remediation}`),
    },
    locations: [
      {
        physicalLocation: { artifactLocation: { uri } },
        logicalLocations: [{ name: sanitize(report.target), kind: 'host' }],
      },
    ],
    properties: { severity: finding.severity, evidence: finding.evidence },
  }));

  const notifications = report.errors.map((error) => ({
    level: 'error' as const,
    message: { text: sanitize(`${error.module}: ${error.code} (${error.message})`) },
  }));

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Sentinel',
            version: sanitize(report.tool.version),
            informationUri: 'https://github.com/MounibAhmedAggoun/Sentinel',
            rules,
          },
        },
        invocations: [
          {
            executionSuccessful: report.errors.length === 0,
            startTimeUtc: report.startedAt,
            endTimeUtc: report.finishedAt,
            toolExecutionNotifications: notifications,
          },
        ],
        results,
      },
    ],
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}
