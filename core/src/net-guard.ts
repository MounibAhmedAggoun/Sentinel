import ipaddr from 'ipaddr.js';

export type IpCheck = { allowed: true; ip: string } | { allowed: false; reason: string };

export function checkIp(input: string): IpCheck {
  let addr: ReturnType<typeof ipaddr.process>;
  try {
    addr = ipaddr.process(input);
  } catch {
    return { allowed: false, reason: 'not a valid IP address' };
  }

  const range = addr.range();
  if (range !== 'unicast') {
    return { allowed: false, reason: `blocked address range: ${range}` };
  }

  return { allowed: true, ip: addr.toString() };
}
