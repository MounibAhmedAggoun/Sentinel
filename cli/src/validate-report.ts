import { readFile, stat } from 'node:fs/promises';
import { reportSchema, type Report } from '@sentinel/scanner';

const MAX_REPORT_BYTES = 10 * 1024 * 1024;
const MAX_ISSUES_SHOWN = 5;

export type ValidateOutcome = { ok: true; report: Report } | { ok: false; error: string };

/** Checks that a file is a valid Sentinel report. Never throws: problems come back as errors. */
export async function validateReportFile(filePath: string): Promise<ValidateOutcome> {
  let text: string;
  try {
    const info = await stat(filePath);
    if (!info.isFile()) return { ok: false, error: 'not a regular file' };
    if (info.size > MAX_REPORT_BYTES) return { ok: false, error: 'file is larger than 10 MB' };
    text = await readFile(filePath, 'utf8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    return { ok: false, error: code === 'ENOENT' ? 'file not found' : 'could not read file' };
  }

  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    return { ok: false, error: 'file is not valid JSON' };
  }

  const parsed = reportSchema.safeParse(data);
  if (parsed.success) return { ok: true, report: parsed.data };

  const issues = parsed.error.issues
    .slice(0, MAX_ISSUES_SHOWN)
    .map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`);
  const more = parsed.error.issues.length - issues.length;
  const suffix = more > 0 ? `; and ${more} more` : '';
  return { ok: false, error: `does not match the report schema: ${issues.join('; ')}${suffix}` };
}
