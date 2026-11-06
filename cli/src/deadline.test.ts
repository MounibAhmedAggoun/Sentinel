import { describe, expect, it } from 'vitest';
import { createDeadline, DeadlineError, parseMaxDuration } from './deadline.js';

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

describe('parseMaxDuration', () => {
  it('accepts whole seconds and returns milliseconds', () => {
    expect(parseMaxDuration('30')).toEqual({ ok: true, ms: 30_000 });
    expect(parseMaxDuration('1')).toEqual({ ok: true, ms: 1000 });
    expect(parseMaxDuration('3600')).toEqual({ ok: true, ms: 3_600_000 });
  });

  it.each(['0', '3601', '-5', '1.5', 'abc', '', '10s', ' 10', '1e3'])('rejects %j', (raw) => {
    expect(parseMaxDuration(raw).ok).toBe(false);
  });
});

describe('createDeadline', () => {
  it('returns the result of a step that finishes in time', async () => {
    const withDeadline = createDeadline(1000);

    expect(await withDeadline(async () => 'done')).toBe('done');
  });

  it('throws DeadlineError when a step runs past the deadline', async () => {
    const withDeadline = createDeadline(50);

    await expect(withDeadline(() => sleep(500))).rejects.toBeInstanceOf(DeadlineError);
  });

  it('throws DeadlineError without starting a step once time is up', async () => {
    const withDeadline = createDeadline(20);
    await sleep(60);
    let started = false;

    await expect(
      withDeadline(async () => {
        started = true;
      }),
    ).rejects.toBeInstanceOf(DeadlineError);
    expect(started).toBe(false);
  });

  it('shares one clock across steps', async () => {
    const withDeadline = createDeadline(120);

    await withDeadline(() => sleep(70));
    await expect(withDeadline(() => sleep(500))).rejects.toBeInstanceOf(DeadlineError);
  });

  it('passes a step error through unchanged', async () => {
    const withDeadline = createDeadline(1000);

    await expect(
      withDeadline(async () => {
        throw new Error('boom');
      }),
    ).rejects.toThrow('boom');
  });
});
