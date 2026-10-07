import { mkdtemp, readFile, readdir, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { evaluate } from '../findings/engine.js';
import { makeScan } from '../findings/fixtures.js';
import { buildReport } from './build.js';
import { reportSchema, type Report } from './schema.js';
import { writeReport } from './write.js';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), 'sentinel-report-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

function sampleReport(): Report {
  const scan = makeScan();
  return buildReport({
    scan,
    findings: evaluate(scan),
    startedAt: new Date('2026-10-01T10:00:00.000Z'),
    finishedAt: new Date('2026-10-01T10:00:01.000Z'),
    toolVersion: '0.1.0',
  });
}

describe('writeReport', () => {
  it('writes a report that reads back and passes the schema', async () => {
    const file = path.join(dir, 'report.json');

    await writeReport(sampleReport(), file);

    const parsed: unknown = JSON.parse(await readFile(file, 'utf8'));
    expect(reportSchema.safeParse(parsed).success).toBe(true);
  });

  it('creates missing folders', async () => {
    const file = path.join(dir, 'a', 'b', 'report.json');

    await writeReport(sampleReport(), file);

    expect((await stat(file)).isFile()).toBe(true);
  });

  it('leaves no temporary files behind', async () => {
    await writeReport(sampleReport(), path.join(dir, 'report.json'));

    expect(await readdir(dir)).toEqual(['report.json']);
  });

  it('makes the file readable only by its owner', async () => {
    const file = path.join(dir, 'report.json');

    await writeReport(sampleReport(), file);

    expect((await stat(file)).mode & 0o777).toBe(0o600);
  });

  it('overwrites an existing report', async () => {
    const file = path.join(dir, 'report.json');

    await writeReport(sampleReport(), file);
    await writeReport({ ...sampleReport(), target: 'other.example.com' }, file);

    const parsed = JSON.parse(await readFile(file, 'utf8')) as Report;
    expect(parsed.target).toBe('other.example.com');
  });

  it('refuses to write an invalid report', async () => {
    const file = path.join(dir, 'bad.json');
    const bad = { ...sampleReport(), schemaVersion: '9.9' } as unknown as Report;

    await expect(writeReport(bad, file)).rejects.toThrow();
    expect(await readdir(dir)).toEqual([]);
  });
});
