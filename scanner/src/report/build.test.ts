import { describe, expect, it } from 'vitest';
import { evaluate } from '../findings/engine.js';
import { makeScan, scanWithHeaders } from '../findings/fixtures.js';
import { buildReport } from './build.js';
import { reportJsonSchema } from './json-schema.js';
import { reportSchema, SCHEMA_VERSION } from './schema.js';

const STARTED = new Date('2026-10-01T10:00:00.000Z');
const FINISHED = new Date('2026-10-01T10:00:02.500Z');

function build(scan = makeScan()) {
  return buildReport({
    scan,
    findings: evaluate(scan),
    startedAt: STARTED,
    finishedAt: FINISHED,
    toolVersion: '0.1.0',
  });
}

describe('buildReport', () => {
  it('produces a report that passes the schema', () => {
    expect(reportSchema.safeParse(build()).success).toBe(true);
  });

  it('records the schema version, tool, target and timing', () => {
    const report = build();

    expect(report.schemaVersion).toBe(SCHEMA_VERSION);
    expect(report.tool).toEqual({ name: 'sentinel', version: '0.1.0' });
    expect(report.target).toBe('example.com');
    expect(report.startedAt).toBe('2026-10-01T10:00:00.000Z');
    expect(report.durationMs).toBe(2500);
  });

  it('includes findings', () => {
    const scan = scanWithHeaders({});
    const report = build(scan);

    expect(report.findings.length).toBeGreaterThan(0);
    expect(report.findings.every((f) => f.remediation !== '')).toBe(true);
  });

  it('has an empty errors list when every check worked', () => {
    expect(build().errors).toEqual([]);
  });

  it('lists failed checks as errors', () => {
    const scan = {
      ...makeScan(),
      tls: { ok: false as const, error: { code: 'TIMEOUT' as const, message: 'slow' } },
      tcp: { ok: false as const, error: { code: 'BLOCKED_TARGET' as const, message: 'blocked' } },
    };

    expect(build(scan).errors).toEqual([
      { module: 'tcp', code: 'BLOCKED_TARGET', message: 'blocked' },
      { module: 'tls', code: 'TIMEOUT', message: 'slow' },
    ]);
  });

  it('treats "no such record" as a normal answer, not an error', () => {
    const base = makeScan();
    const scan = {
      ...base,
      dns: {
        ...base.dns,
        caa: { ok: false as const, error: { code: 'NODATA' as const, message: 'x' } },
      },
    };

    expect(build(scan).errors).toEqual([]);
  });

  it('lists DNS timeouts as errors', () => {
    const base = makeScan();
    const scan = {
      ...base,
      dns: {
        ...base.dns,
        mx: { ok: false as const, error: { code: 'TIMEOUT' as const, message: 'slow' } },
      },
    };

    expect(build(scan).errors).toEqual([{ module: 'dns.mx', code: 'TIMEOUT', message: 'slow' }]);
  });

  it('lists HTTP failures as errors', () => {
    const base = makeScan();
    const scan = {
      ...base,
      httpPlain: { ...base.httpPlain, error: { code: 'TIMEOUT' as const, message: 'slow' } },
    };

    expect(build(scan).errors).toEqual([{ module: 'httpPlain', code: 'TIMEOUT', message: 'slow' }]);
  });

  it('never puts cookie values in the report', () => {
    const scan = scanWithHeaders({ 'set-cookie': ['sid=SUPERSECRET123; Secure; HttpOnly'] });
    const text = JSON.stringify(build(scan));

    expect(text).not.toContain('SUPERSECRET123');
    expect(text).toContain('sid=[redacted]');
  });

  it('redacts every cookie when there are several', () => {
    const scan = scanWithHeaders({ 'set-cookie': ['a=ONE; Secure', 'b=TWO; HttpOnly'] });
    const text = JSON.stringify(build(scan));

    expect(text).not.toContain('ONE');
    expect(text).not.toContain('TWO');
  });

  it('does not change the scan it was given', () => {
    const scan = scanWithHeaders({ 'set-cookie': ['sid=KEEPME; Secure'] });
    build(scan);

    expect(scan.http.hops[0]?.headers['set-cookie']).toEqual(['sid=KEEPME; Secure']);
  });

  it('is deterministic for the same input', () => {
    expect(build()).toEqual(build());
  });

  it('matches a snapshot', () => {
    expect(build(scanWithHeaders({ server: 'Apache/2.4.41' }))).toMatchSnapshot();
  });
});

describe('reportSchema', () => {
  it('rejects a report with the wrong schema version', () => {
    expect(reportSchema.safeParse({ ...build(), schemaVersion: '9.9' }).success).toBe(false);
  });

  it('rejects a report with a missing field', () => {
    const { findings: _removed, ...rest } = build();

    expect(reportSchema.safeParse(rest).success).toBe(false);
  });

  it('rejects an invalid severity', () => {
    const report = build(scanWithHeaders({}));
    const bad = { ...report, findings: [{ ...report.findings[0], severity: 'critical' }] };

    expect(reportSchema.safeParse(bad).success).toBe(false);
  });
});

describe('reportJsonSchema', () => {
  it('exports a JSON Schema document', () => {
    const schema = reportJsonSchema();

    expect(schema['$schema']).toContain('json-schema.org');
    expect(schema['title']).toBe('Sentinel scan report');
    expect(schema['type']).toBe('object');
    expect(Object.keys(schema['properties'] as object)).toContain('findings');
  });
});
