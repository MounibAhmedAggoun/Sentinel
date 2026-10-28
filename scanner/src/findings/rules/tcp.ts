import { RULE_IDS } from '../ids.js';
import type { Finding, Rule } from '../types.js';

/** Ports whose services are commonly meant to be reached from the internet. */
const EXPECTED_PUBLIC_PORTS = new Set([80, 443]);

interface PortPolicy {
  severity: 'low' | 'medium';
  service: string;
  reason: string;
}

/**
 * Severity by port, for services where being reachable from the internet is
 * more unusual or more consequential than a typical web port. This still
 * only says what was observed - a reachable port - never that the service
 * is actually vulnerable or that anyone has accessed it.
 */
const SENSITIVE_PORTS: Record<number, PortPolicy> = {
  21: {
    severity: 'low',
    service: 'FTP',
    reason: 'FTP commonly transmits credentials in plain text.',
  },
  23: {
    severity: 'medium',
    service: 'Telnet',
    reason: 'Telnet is an unencrypted remote administration protocol.',
  },
  3389: {
    severity: 'medium',
    service: 'RDP',
    reason: 'RDP provides remote desktop access to the machine.',
  },
  3306: {
    severity: 'medium',
    service: 'MySQL',
    reason:
      'This is a database port, which is usually meant to be reached only from inside a private network.',
  },
  5432: {
    severity: 'medium',
    service: 'PostgreSQL',
    reason:
      'This is a database port, which is usually meant to be reached only from inside a private network.',
  },
  6379: {
    severity: 'medium',
    service: 'Redis',
    reason:
      'This is a data store port, which is usually meant to be reached only from inside a private network.',
  },
  27017: {
    severity: 'medium',
    service: 'MongoDB',
    reason:
      'This is a database port, which is usually meant to be reached only from inside a private network.',
  },
};

export const tcpRules: Rule = (scan) => {
  if (!scan.tcp.ok) return [];

  const { ip, ports } = scan.tcp.result;
  const findings: Finding[] = [];

  for (const result of ports) {
    if (result.state !== 'open') continue;

    const policy = SENSITIVE_PORTS[result.port];
    const expected = EXPECTED_PUBLIC_PORTS.has(result.port);
    const evidence = { port: result.port, state: result.state, ip, timingMs: result.timingMs };

    if (policy !== undefined) {
      findings.push({
        ruleId: RULE_IDS.TCP_SENSITIVE_PORT_OPEN,
        title: `${policy.service} port ${result.port} observed open`,
        severity: policy.severity,
        description: `Port ${result.port} (${policy.service}) on ${scan.target} accepted a TCP connection, meaning it is reachable from the scanning host. ${policy.reason} This is an observation of reachability, not proof the service is misconfigured or has been accessed.`,
        evidence,
        remediation:
          'Confirm this service is meant to be reachable from where this scan ran. If not, restrict it with a firewall or move it to a private network.',
      });
      continue;
    }

    findings.push({
      ruleId: RULE_IDS.TCP_PORT_OPEN,
      title: `TCP port ${result.port} observed open`,
      severity: 'informational',
      description: expected
        ? `Port ${result.port} on ${scan.target} accepted a TCP connection. This is normal for a web server.`
        : `Port ${result.port} on ${scan.target} accepted a TCP connection. An open port is not a weakness by itself. Whether it matters depends on what service is behind it and who is meant to reach it.`,
      evidence,
      remediation: expected
        ? 'No action needed if this port is meant to be public.'
        : 'Confirm this service is meant to be reachable from the internet. If it is not, consider restricting it with a firewall.',
    });
  }

  return findings;
};
