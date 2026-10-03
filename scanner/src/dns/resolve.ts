import { Resolver } from 'node:dns/promises';
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

export async function resolveDns(
  hostname: string,
  resolver: DnsResolver = new Resolver({ timeout: 3000, tries: 2 }),
): Promise<DnsResult> {
  const [a, aaaa, mx, ns, txt, caa, dmarcTxt] = await Promise.all([
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
    attempt<CaaRecord>(async () => (await resolver.resolveCaa(hostname)).map(normalizeCaa)),
    lookupTxt(resolver, `_dmarc.${hostname}`),
  ]);

  return {
    hostname,
    a,
    aaaa,
    mx,
    ns,
    txt,
    caa,
    spf: txt.ok ? parseSpf(txt.records) : null,
    dmarc: dmarcTxt.ok ? parseDmarc(dmarcTxt.records) : null,
  };
}
