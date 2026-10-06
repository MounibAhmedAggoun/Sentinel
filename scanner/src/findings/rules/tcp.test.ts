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

  it('reports an open port as informational', () => {
    const findings = tcpRules(withPorts([port(3306, 'open')]));

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: RULE_IDS.TCP_PORT_OPEN,
      severity: 'informational',
      evidence: { port: 3306, state: 'open', ip: '93.184.216.34' },
    });
    expect(findings[0]?.remediation).not.toBe('');
  });

  it('never rates an open port above informational', () => {
    const findings = tcpRules(
      withPorts([21, 22, 25, 3306, 5432, 8080].map((p) => port(p, 'open'))),
    );

    expect(findings).toHaveLength(6);
    expect(findings.every((f) => f.severity === 'informational')).toBe(true);
  });

  it('uses calmer wording for ports 80 and 443', () => {
    const findings = tcpRules(withPorts([port(443, 'open'), port(5432, 'open')]));

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
    for (const finding of tcpRules(withPorts([port(3306, 'open')]))) {
      expect(`${finding.title} ${finding.description}`.toLowerCase()).not.toContain('vulnerab');
    }
  });
});
