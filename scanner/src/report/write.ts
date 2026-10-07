import { mkdir, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { reportSchema, type Report } from './schema.js';

/**
 * Validates a report and writes it as JSON. The file is written to a temporary
 * name first and then renamed, so a crash never leaves a half-written report.
 */
export async function writeReport(report: Report, filePath: string): Promise<void> {
  // Never write something that breaks our own format.
  const valid = reportSchema.parse(report);

  const resolved = path.resolve(filePath);
  await mkdir(path.dirname(resolved), { recursive: true });

  const temp = `${resolved}.${process.pid}.tmp`;
  await writeFile(temp, `${JSON.stringify(valid, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  await rename(temp, resolved);
}
