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
