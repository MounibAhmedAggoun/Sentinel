import type { ScanResult } from '@sentinel/scanner';

/**
 * Counts how many of the 5 top-level scan modules (dns, http, httpPlain, tcp,
 * tls) produced no usable result. DNS is special: it runs 7 separate lookups
 * (a, aaaa, mx, ns, txt, caa, dmarcTxt), so it only counts as failed when
 * every one of them errored - a handful of individual DNS errors should not
 * look like a total scan failure.
 */
export function countFailedModules(scan: ScanResult): number {
  const dnsLookups = [
    scan.dns.a,
    scan.dns.aaaa,
    scan.dns.mx,
    scan.dns.ns,
    scan.dns.txt,
    scan.dns.caa,
    scan.dns.dmarcTxt,
  ];
  const dnsFailed = dnsLookups.every((lookup) => !lookup.ok);

  let failed = 0;
  if (dnsFailed) failed++;
  if (scan.http.error !== null) failed++;
  if (scan.httpPlain.error !== null) failed++;
  if (!scan.tcp.ok) failed++;
  if (!scan.tls.ok) failed++;

  return failed;
}
