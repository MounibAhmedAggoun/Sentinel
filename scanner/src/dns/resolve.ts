import { Resolver } from 'node:dns/promises';
import { domainAncestors } from './domain.js';
import { toDnsError } from './errors.js';
import { parseDmarc, parseSpf } from './parsers.js';
import type { CaaRecord, DnsLookup, DnsResult, MxRecord } from './types.js';

export type DnsResolver = Pick<
  Resolver,
  'resolve4' | 'resolve6' | 'resolveMx' | 'resolveNs' | 'resolveTxt' | 'resolveCaa'
>;

async function attempt<T>(fn: () => Promise<T[]>): Promise<DnsLookup<T>> {
  try {
    return { ok: true, records: await fn() };
  } catch (err) {
    return { ok: false, error: toDnsError(err) };
  }
}

async function lookupTxt(resolver: DnsResolver, name: string): Promise<DnsLookup<string>> {
  // A TXT record can be split into chunks. Join them back into one string.
  return attempt(async () => (await resolver.resolveTxt(name)).map((chunks) => chunks.join('')));
}

function normalizeCaa(record: object): CaaRecord {
  const entries = Object.entries(record as Record<string, unknown>);
  const critical = entries.some(([key, value]) => key === 'critical' && value === 128);
  const tagEntry = entries.find(([key, value]) => key !== 'critical' && typeof value === 'string');
  return { critical, tag: tagEntry?.[0] ?? '', value: String(tagEntry?.[1] ?? '') };
}

/**
 * CAA lookups climb the label tree (RFC 8659): if "www.example.com" has no CAA
 * records, check "example.com" next, and so on, stopping at the first domain
 * that clearly has an answer (records, or a confirmed empty set). A lookup
 * error (timeout, SERVFAIL) stops the walk immediately rather than guessing.
 */
async function resolveCaaWithFallback(
  resolver: DnsResolver,
  hostname: string,
): Promise<{ lookup: DnsLookup<CaaRecord>; foundAt: string | null }> {
  for (const candidate of domainAncestors(hostname)) {
    const lookup = await attempt<CaaRecord>(async () =>
      (await resolver.resolveCaa(candidate)).map(normalizeCaa),
    );

    if (!lookup.ok) {
      if (lookup.error.code === 'NODATA' || lookup.error.code === 'NXDOMAIN') continue;
      return { lookup, foundAt: null };
    }
    if (lookup.records.length === 0) continue;

    return { lookup, foundAt: candidate };
  }

  // No ancestor had records. Report "absent" against the original hostname.
  return { lookup: { ok: true, records: [] }, foundAt: null };
}

/**
 * DMARC lives at _dmarc.<hostname>, but is usually only published at the
 * organizational domain (RFC 7489). If "_dmarc.www.example.com" has no
 * record, fall back to "_dmarc.example.com" before concluding it's absent.
 */
async function resolveDmarcWithFallback(
  resolver: DnsResolver,
  hostname: string,
): Promise<{ lookup: DnsLookup<string>; foundAt: string | null }> {
  const candidates = [...new Set(domainAncestors(hostname))];

  for (const candidate of candidates) {
    const lookup = await lookupTxt(resolver, `_dmarc.${candidate}`);

    if (!lookup.ok) {
      if (lookup.error.code === 'NODATA' || lookup.error.code === 'NXDOMAIN') continue;
      return { lookup, foundAt: null };
    }
    if (lookup.records.length === 0) continue;

    return { lookup, foundAt: candidate };
  }

  return { lookup: { ok: true, records: [] }, foundAt: null };
}

export async function resolveDns(
  hostname: string,
  resolver: DnsResolver = new Resolver({ timeout: 3000, tries: 2 }),
): Promise<DnsResult> {
  const [a, aaaa, mx, ns, txt, caaResult, dmarcResult] = await Promise.all([
    attempt<string>(() => resolver.resolve4(hostname)),
    attempt<string>(() => resolver.resolve6(hostname)),
    attempt<MxRecord>(async () =>
      (await resolver.resolveMx(hostname)).map(({ exchange, priority }) => ({
        exchange,
        priority,
      })),
    ),
    attempt<string>(() => resolver.resolveNs(hostname)),
    lookupTxt(resolver, hostname),
    resolveCaaWithFallback(resolver, hostname),
    resolveDmarcWithFallback(resolver, hostname),
  ]);

  return {
    hostname,
    a,
    aaaa,
    mx,
    ns,
    txt,
    caa: caaResult.lookup,
    caaFoundAt: caaResult.foundAt,
    dmarcTxt: dmarcResult.lookup,
    dmarcFoundAt: dmarcResult.foundAt,
    spf: txt.ok ? parseSpf(txt.records) : null,
    dmarc: dmarcResult.lookup.ok ? parseDmarc(dmarcResult.lookup.records) : null,
  };
}
