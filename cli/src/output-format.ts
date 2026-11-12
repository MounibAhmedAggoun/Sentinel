export const OUTPUT_FORMATS = ['table', 'markdown', 'html'] as const;

export type OutputFormat = (typeof OUTPUT_FORMATS)[number];

export type FormatParse = { ok: true; format: OutputFormat } | { ok: false; error: string };

/** Parses the --format flag. Only the listed names are accepted, exactly as written. */
export function parseFormat(raw: string): FormatParse {
  const found = OUTPUT_FORMATS.find((format) => format === raw);
  if (found === undefined) {
    return { ok: false, error: `format must be one of: ${OUTPUT_FORMATS.join(', ')}` };
  }
  return { ok: true, format: found };
}
