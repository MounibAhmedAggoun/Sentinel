import { randomUUID } from 'node:crypto';
import { mkdir, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { reportSchema, type Report } from './schema.js';

/**
 * Validates a report and writes it as JSON. The file is written to a temporary
 * name first and then renamed, so a crash never leaves a half-written report.
 * The temporary name is random and created with the "wx" flag, so an existing
 * file or symlink at that path is never followed or overwritten.
 */
export async function writeReport(report: Report, filePath: string): Promise<void> {
  // Never write something that breaks our own format.
  const valid = reportSchema.parse(report);

  const resolved = path.resolve(filePath);
  await mkdir(path.dirname(resolved), { recursive: true });

  const temp = `${resolved}.${randomUUID()}.tmp`;
  try {
    await writeFile(temp, `${JSON.stringify(valid, null, 2)}\n`, {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx',
    });
    await rename(temp, resolved);
  } catch (err) {
    await rm(temp, { force: true });
    throw err;
  }
}
