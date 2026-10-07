import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildReport, evaluate } from '@sentinel/scanner';
import { validateReportFile } from './validate-report.js';

// The scanner's test fixtures are not exported, so build a minimal valid scan here.
import { makeScan } from '../../scanner/src/findings/fixtures.js';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), 'sentinel-validate-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

function validReport() {
  const scan = makeScan();
  return buildReport({
    scan,
    findings: evaluate(scan),
    startedAt: new Date('2026-10-01T10:00:00.000Z'),
    finishedAt: new Date('2026-10-01T10:00:01.000Z'),
    toolVersion: '0.1.0',
  });
}

async function write(name: string, content: string): Promise<string> {
  const file = path.join(dir, name);
  await writeFile(file, content);
  return file;
}

describe('validateReportFile', () => {
  it('accepts a valid report', async () => {
    const file = await write('ok.json', JSON.stringify(validReport()));

    const outcome = await validateReportFile(file);

    expect(outcome.ok).toBe(true);
    expect(outcome.ok && outcome.report.target).toBe('example.com');
  });

  it('reports a missing file', async () => {
    expect(await validateReportFile(path.join(dir, 'nope.json'))).toEqual({
      ok: false,
      error: 'file not found',
    });
  });

  it('rejects a directory', async () => {
    expect(await validateReportFile(dir)).toEqual({ ok: false, error: 'not a regular file' });
  });

  it('rejects text that is not JSON', async () => {
    const file = await write('bad.json', '{ not json');

    expect(await validateReportFile(file)).toEqual({ ok: false, error: 'file is not valid JSON' });
  });

  it('rejects JSON that is not a report', async () => {
    const file = await write('other.json', JSON.stringify({ hello: 'world' }));

    const outcome = await validateReportFile(file);

    expect(outcome.ok).toBe(false);
    expect(!outcome.ok && outcome.error).toContain('does not match the report schema');
  });

  it('names the problem when the schema version is wrong', async () => {
    const file = await write('v.json', JSON.stringify({ ...validReport(), schemaVersion: '9.9' }));

    const outcome = await validateReportFile(file);

    expect(!outcome.ok && outcome.error).toContain('schemaVersion');
  });

  it('limits how many problems it lists', async () => {
    const file = await write('empty.json', JSON.stringify({}));

    const outcome = await validateReportFile(file);

    expect(!outcome.ok && outcome.error).toMatch(/and \d+ more/);
  });

  it('rejects a file over 10 MB without reading it', async () => {
    const file = await write('huge.json', 'x'.repeat(10 * 1024 * 1024 + 1));

    expect(await validateReportFile(file)).toEqual({
      ok: false,
      error: 'file is larger than 10 MB',
    });
  });
});
