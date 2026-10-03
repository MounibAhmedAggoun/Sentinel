import type { DmarcRecord, SpfRecord } from './types.js';

/** Finds the SPF record among TXT values and extracts its "all" mechanism. */
export function parseSpf(txtRecords: string[]): SpfRecord | null {
  const raw = txtRecords.find((r) => /^v=spf1(\s|$)/i.test(r.trim()));
  if (raw === undefined) return null;

  const match = /(?:^|\s)([+\-~?]?)all(?:\s|$)/i.exec(raw);
  if (!match) return { raw, all: null };

  const qualifier = match[1] === '' ? '+' : match[1];
  return { raw, all: `${qualifier}all` as SpfRecord['all'] };
}

/** Finds the DMARC record among TXT values and extracts its policy (p=). */
export function parseDmarc(txtRecords: string[]): DmarcRecord | null {
  const raw = txtRecords.find((r) => /^v=DMARC1\s*(;|$)/i.test(r.trim()));
  if (raw === undefined) return null;

  const match = /(?:^|;)\s*p\s*=\s*(none|quarantine|reject)\s*(?:;|$)/i.exec(raw);
  const policy = match?.[1]?.toLowerCase() as DmarcRecord['policy'] | undefined;
  return { raw, policy: policy ?? null };
}
