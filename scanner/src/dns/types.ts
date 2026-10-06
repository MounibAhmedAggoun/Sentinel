export type DnsErrorCode = 'NXDOMAIN' | 'NODATA' | 'TIMEOUT' | 'SERVFAIL' | 'REFUSED' | 'UNKNOWN';

export interface DnsError {
  code: DnsErrorCode;
  message: string;
}

/** Every lookup returns records or a structured error. It never throws. */
export type DnsLookup<T> = { ok: true; records: T[] } | { ok: false; error: DnsError };

export interface MxRecord {
  exchange: string;
  priority: number;
}

export interface CaaRecord {
  critical: boolean;
  tag: string;
  value: string;
}

export interface SpfRecord {
  raw: string;
  /** The "all" mechanism: "-all", "~all", "?all", "+all", or null if missing. */
  all: '-all' | '~all' | '?all' | '+all' | null;
}

export interface DmarcRecord {
  raw: string;
  policy: 'none' | 'quarantine' | 'reject' | null;
}

export interface DnsResult {
  hostname: string;
  a: DnsLookup<string>;
  aaaa: DnsLookup<string>;
  mx: DnsLookup<MxRecord>;
  ns: DnsLookup<string>;
  txt: DnsLookup<string>;
  caa: DnsLookup<CaaRecord>;
  dmarcTxt: DnsLookup<string>;
  spf: SpfRecord | null;
  dmarc: DmarcRecord | null;
}
