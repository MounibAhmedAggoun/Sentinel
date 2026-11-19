export type RuleListParse = { ok: true; ids: string[] } | { ok: false; error: string };

/**
 * Parses a comma-separated list of rule IDs such as "HTTP-001,TLS-002".
 * Only IDs from the catalog are accepted, exactly as written.
 */
export function parseRuleList(raw: string, known: readonly string[]): RuleListParse {
  const parts = raw.split(',');

  if (parts.some((part) => part === '')) {
    return { ok: false, error: 'rule list has an empty entry' };
  }

  const unknown = parts.filter((part) => !known.includes(part));
  if (unknown.length > 0) {
    return { ok: false, error: `unknown rule(s): ${unknown.join(', ')}` };
  }

  return { ok: true, ids: [...new Set(parts)] };
}

/** Keeps only the listed rules (only), or drops the listed rules (skip). */
export function filterFindings<T extends { ruleId: string }>(
  findings: readonly T[],
  filter: { only?: readonly string[]; skip?: readonly string[] },
): T[] {
  const { only, skip } = filter;
  return findings.filter((finding) => {
    if (only !== undefined && !only.includes(finding.ruleId)) return false;
    if (skip !== undefined && skip.includes(finding.ruleId)) return false;
    return true;
  });
}

const SEVERITY_ORDER: Record<string, number> = { high: 0, medium: 1, low: 2, informational: 3 };

/**
 * Marks sensitive-port findings (TCP-002) for ports the owner listed as expected.
 * They stay in the report at informational severity, with a note in the description.
 * The list is sorted again, because a lower severity changes the order.
 */
export function markExpectedPorts<
  T extends {
    ruleId: string;
    severity: string;
    description: string;
    evidence: Record<string, unknown>;
  },
>(findings: readonly T[], expectedPorts: readonly number[]): T[] {
  if (expectedPorts.length === 0) return [...findings];

  const marked = findings.map((finding) => {
    const port = finding.evidence['port'];
    if (finding.ruleId !== 'TCP-002' || typeof port !== 'number' || !expectedPorts.includes(port)) {
      return finding;
    }
    return {
      ...finding,
      severity: 'informational',
      description: `${finding.description} This port was marked as expected with --expected-ports, so it is reported as informational.`,
      evidence: { ...finding.evidence, expected: true },
    } as T;
  });

  // Array.prototype.sort is stable, so ties keep their order.
  return marked.sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4),
  );
}
