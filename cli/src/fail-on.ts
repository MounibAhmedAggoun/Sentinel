export const SEVERITY_ORDER = ['informational', 'low', 'medium', 'high'] as const;

export type Severity = (typeof SEVERITY_ORDER)[number];

/** Today's behavior: informational findings never fail a scan, low and above do. */
export const DEFAULT_FAIL_ON: Severity = 'low';

export type FailOnParse = { ok: true; severity: Severity } | { ok: false; error: string };

/** Parses the --fail-on flag. Only the listed names are accepted, exactly as written. */
export function parseFailOn(raw: string): FailOnParse {
  const found = SEVERITY_ORDER.find((severity) => severity === raw);
  if (found === undefined) {
    return { ok: false, error: `fail-on must be one of: ${SEVERITY_ORDER.join(', ')}` };
  }
  return { ok: true, severity: found };
}

/** True when any finding is at or above the threshold severity. */
export function hasFindingsAtOrAbove(
  findings: readonly { severity: Severity }[],
  threshold: Severity,
): boolean {
  const minimum = SEVERITY_ORDER.indexOf(threshold);
  return findings.some((finding) => SEVERITY_ORDER.indexOf(finding.severity) >= minimum);
}
