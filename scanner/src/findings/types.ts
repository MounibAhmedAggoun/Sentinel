import type { Severity } from '@sentinel/core';
import type { DnsResult } from '../dns/types.js';
import type { HttpResult } from '../http/types.js';
import type { TcpScanOutcome } from '../tcp/scan.js';
import type { TlsOutcome } from '../tls/types.js';

/** Everything the scanner collected for one target. Rules read this and nothing else. */
export interface ScanResult {
  target: string;
  dns: DnsResult;
  http: HttpResult;
  tcp: TcpScanOutcome;
  tls: TlsOutcome;
}

export interface Finding {
  /** Stable ID such as "HTTP-001". */
  ruleId: string;
  title: string;
  severity: Severity;
  /** What was observed and why it may matter. Never claims exploitability. */
  description: string;
  /** The raw observation that supports the finding. */
  evidence: Record<string, unknown>;
  /** What the authorized owner can investigate or change. */
  remediation: string;
}

/** A rule is a pure function: same scan result in, same findings out. */
export type Rule = (scan: ScanResult) => Finding[];
