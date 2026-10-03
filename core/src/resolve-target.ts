import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { checkIp, type CheckOptions } from './net-guard.js';

export type ResolveResult =
  { allowed: true; hostname: string; ips: string[] } | { allowed: false; reason: string };

export async function resolveTarget(
  target: string,
  options: CheckOptions = {},
): Promise<ResolveResult> {
  if (isIP(target)) {
    const check = checkIp(target, options);
    return check.allowed ? { allowed: true, hostname: target, ips: [check.ip] } : check;
  }

  let records: { address: string }[];
  try {
    records = await lookup(target, { all: true });
  } catch {
    return { allowed: false, reason: 'hostname did not resolve' };
  }

  if (records.length === 0) {
    return { allowed: false, reason: 'hostname did not resolve' };
  }

  const ips: string[] = [];
  for (const record of records) {
    const check = checkIp(record.address, options);
    if (!check.allowed) {
      return { allowed: false, reason: `${target} resolves to ${record.address}: ${check.reason}` };
    }
    ips.push(check.ip);
  }

  return { allowed: true, hostname: target, ips };
}
