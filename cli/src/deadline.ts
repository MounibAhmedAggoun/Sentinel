/** Thrown when a scan runs past its maximum duration. */
export class DeadlineError extends Error {
  constructor() {
    super('scan exceeded the maximum duration');
    this.name = 'DeadlineError';
  }
}

export const DEFAULT_MAX_DURATION_SECONDS = 120;
const MAX_ALLOWED_SECONDS = 3600;

export type DurationParse = { ok: true; ms: number } | { ok: false; error: string };

/** Parses the --max-duration flag (whole seconds, 1 to 3600). */
export function parseMaxDuration(raw: string): DurationParse {
  if (!/^\d+$/.test(raw)) {
    return { ok: false, error: 'max duration must be a whole number of seconds' };
  }
  const seconds = Number(raw);
  if (seconds < 1 || seconds > MAX_ALLOWED_SECONDS) {
    return {
      ok: false,
      error: `max duration must be between 1 and ${MAX_ALLOWED_SECONDS} seconds`,
    };
  }
  return { ok: true, ms: seconds * 1000 };
}

/**
 * Starts a deadline clock. The returned function runs one step and throws
 * DeadlineError if the deadline has already passed or passes while it runs.
 */
export function createDeadline(maxMs: number): <T>(run: () => Promise<T>) => Promise<T> {
  const endsAt = Date.now() + maxMs;

  return async function withDeadline<T>(run: () => Promise<T>): Promise<T> {
    const remaining = endsAt - Date.now();
    if (remaining <= 0) throw new DeadlineError();

    let timer: NodeJS.Timeout | undefined;
    const expired = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new DeadlineError()), remaining);
    });

    try {
      return await Promise.race([run(), expired]);
    } finally {
      clearTimeout(timer);
    }
  };
}
