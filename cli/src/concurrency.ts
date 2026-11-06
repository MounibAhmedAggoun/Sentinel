export type ConcurrencyParse = { ok: true; value: number } | { ok: false; error: string };

const MAX_CONCURRENCY = 20;

/** Parses the --concurrency flag (a whole number, 1 to 20). */
export function parseConcurrency(raw: string): ConcurrencyParse {
  if (!/^\d+$/.test(raw)) {
    return { ok: false, error: 'concurrency must be a whole number' };
  }
  const value = Number(raw);
  if (value < 1 || value > MAX_CONCURRENCY) {
    return { ok: false, error: `concurrency must be between 1 and ${MAX_CONCURRENCY}` };
  }
  return { ok: true, value };
}
