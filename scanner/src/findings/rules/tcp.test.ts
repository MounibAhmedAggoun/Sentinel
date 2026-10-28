import { describe, expect, it } from 'vitest';
import type { PortResult } from '../../tcp/types.js';
import { makeScan } from '../fixtures.js';
import { RULE_IDS } from '../ids.js';
import type { ScanResult } from '../types.js';
import { tcpRules } from './tcp.js';

function withPorts(ports: PortResult[]): ScanResult {
  return { ...makeScan(), tcp: { ok: true, result: { ip: '93.184.216.34', ports } } };
}

const port = (p: number, state: PortResult['state']): PortResult => ({
  port: p,
  state,
  timingMs: 5,
});

describe('tcpRules', () => {
  it('produces nothing when no ports were checked', () => {
    expect(tcpRules(makeScan())).toEqual([]);
  });

  it('ignores closed, timed out and errored ports', () => {
    const findings = tcpRules(
      withPorts([port(22, 'closed'), port(25, 'timeout'), port(21, 'error')]),
    );

    expect(findings).toEqual([]);
  });

  it('reports a non-sensitive open port as informational', () => {
    const findings = tcpRules(withPorts([port(22, 'open')]));

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: RULE_IDS.TCP_PORT_OPEN,
      severity: 'informational',
      evidence: { port: 22, state: 'open', ip: '93.184.216.34' },
    });
    expect(findings[0]?.remediation).not.toBe('');
  });

  it('never rates a non-sensitive open port above informational', () => {
    const findings = tcpRules(withPorts([22, 25, 8080].map((p) => port(p, 'open'))));

    expect(findings).toHaveLength(3);
    expect(findings.every((f) => f.severity === 'informational')).toBe(true);
    expect(findings.every((f) => f.ruleId === RULE_IDS.TCP_PORT_OPEN)).toBe(true);
  });

  it('uses calmer wording for ports 80 and 443', () => {
    const findings = tcpRules(withPorts([port(443, 'open'), port(22, 'open')]));

    expect(findings[0]?.description).toContain('normal for a web server');
    expect(findings[1]?.description).not.toContain('normal for a web server');
    expect(findings[0]?.remediation).toContain('No action needed');
  });

  it('reports one finding per open port, in order', () => {
    const findings = tcpRules(withPorts([port(22, 'closed'), port(80, 'open'), port(443, 'open')]));

    expect(findings.map((f) => f.evidence['port'])).toEqual([80, 443]);
  });

  it('produces nothing when the TCP scan failed', () => {
    const scan: ScanResult = {
      ...makeScan(),
      tcp: { ok: false, error: { code: 'BLOCKED_TARGET', message: 'blocked' } },
    };

    expect(tcpRules(scan)).toEqual([]);
  });

  it('never claims a vulnerability', () => {
    for (const finding of tcpRules(withPorts([port(3306, 'open'), port(23, 'open')]))) {
      expect(`${finding.title} ${finding.description}`.toLowerCase()).not.toContain('vulnerab');
    }
  });

  describe('sensitive port severity table', () => {
    it.each([
      [21, 'low'],
      [23, 'medium'],
      [3389, 'medium'],
      [3306, 'medium'],
      [5432, 'medium'],
      [6379, 'medium'],
      [27017, 'medium'],
    ] as const)('rates port %i as %s with a distinct rule ID', (portNumber, severity) => {
      const findings = tcpRules(withPorts([port(portNumber, 'open')]));

      expect(findings).toHaveLength(1);
      expect(findings[0]?.ruleId).toBe(RULE_IDS.TCP_SENSITIVE_PORT_OPEN);
      expect(findings[0]?.severity).toBe(severity);
    });

    it('names the service in the title and evidence stays observational', () => {
      const findings = tcpRules(withPorts([port(3389, 'open')]));

      expect(findings[0]?.title).toContain('RDP');
      expect(findings[0]?.description).toContain('observation of reachability');
      expect(findings[0]?.description).not.toContain('exposed to attackers');
    });

    it('does not report a sensitive port above medium severity', () => {
      const allSensitive = [21, 23, 3389, 3306, 5432, 6379, 27017];
      const findings = tcpRules(withPorts(allSensitive.map((p) => port(p, 'open'))));

      expect(findings).toHaveLength(allSensitive.length);
      expect(findings.every((f) => f.severity === 'low' || f.severity === 'medium')).toBe(true);
    });

    it('keeps SSH as informational even though it is also an administrative port', () => {
      const findings = tcpRules(withPorts([port(22, 'open')]));

      expect(findings[0]?.ruleId).toBe(RULE_IDS.TCP_PORT_OPEN);
      expect(findings[0]?.severity).toBe('informational');
    });
  });
});
