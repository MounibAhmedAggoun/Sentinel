export type TimeoutParse = { ok: true; ms: number } | { ok: false; error: string };

const MAX_TIMEOUT_SECONDS = 60;

/** Parses the --timeout flag (whole seconds, 1 to 60) into milliseconds. */
export function parseTimeout(raw: string): TimeoutParse {
  if (!/^\d+$/.test(raw)) {
    return { ok: false, error: 'timeout must be a whole number of seconds' };
  }
  const seconds = Number(raw);
  if (seconds < 1 || seconds > MAX_TIMEOUT_SECONDS) {
    return { ok: false, error: `timeout must be between 1 and ${MAX_TIMEOUT_SECONDS} seconds` };
  }
  return { ok: true, ms: seconds * 1000 };
}
