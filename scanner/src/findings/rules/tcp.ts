import { RULE_IDS } from '../ids.js';
import type { Finding, Rule } from '../types.js';

/** Ports whose services are commonly meant to be reached from the internet. */
const EXPECTED_PUBLIC_PORTS = new Set([80, 443]);

export const tcpRules: Rule = (scan) => {
  if (!scan.tcp.ok) return [];

  const { ip, ports } = scan.tcp.result;
  const findings: Finding[] = [];

  for (const result of ports) {
    if (result.state !== 'open') continue;

    const expected = EXPECTED_PUBLIC_PORTS.has(result.port);
    findings.push({
      ruleId: RULE_IDS.TCP_PORT_OPEN,
      title: `TCP port ${result.port} observed open`,
      severity: 'informational',
      description: expected
        ? `Port ${result.port} on ${scan.target} accepted a TCP connection. This is normal for a web server.`
        : `Port ${result.port} on ${scan.target} accepted a TCP connection. An open port is not a weakness by itself. Whether it matters depends on what service is behind it and who is meant to reach it.`,
      evidence: { port: result.port, state: result.state, ip, timingMs: result.timingMs },
      remediation: expected
        ? 'No action needed if this port is meant to be public.'
        : 'Confirm this service is meant to be reachable from the internet. If it is not, consider restricting it with a firewall.',
    });
  }

  return findings;
};
