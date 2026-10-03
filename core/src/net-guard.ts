import ipaddr from 'ipaddr.js';

export type IpCheck = { allowed: true; ip: string } | { allowed: false; reason: string };

export interface CheckOptions {
  allowPrivate?: boolean;
}

// Ranges that --allow-private unlocks for local testing.
// Link-local (169.254.x.x, cloud metadata) stays blocked even then.
const LOCAL_RANGES = new Set(['private', 'loopback', 'uniqueLocal']);

export function checkIp(input: string, options: CheckOptions = {}): IpCheck {
  let addr: ReturnType<typeof ipaddr.process>;
  try {
    addr = ipaddr.process(input);
  } catch {
    return { allowed: false, reason: 'not a valid IP address' };
  }

  const range = addr.range();
  if (range === 'unicast' || (options.allowPrivate && LOCAL_RANGES.has(range))) {
    return { allowed: true, ip: addr.toString() };
  }

  return { allowed: false, reason: `blocked address range: ${range}` };
}
