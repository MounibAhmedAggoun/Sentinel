import { describe, expect, it } from 'vitest';
import { parseConcurrency } from './concurrency.js';

describe('parseConcurrency', () => {
  it('accepts whole numbers from 1 to 20', () => {
    expect(parseConcurrency('1')).toEqual({ ok: true, value: 1 });
    expect(parseConcurrency('5')).toEqual({ ok: true, value: 5 });
    expect(parseConcurrency('20')).toEqual({ ok: true, value: 20 });
  });

  it.each(['0', '21', '-1', '2.5', 'abc', '', '5x', ' 5', '1e1'])('rejects %j', (raw) => {
    expect(parseConcurrency(raw).ok).toBe(false);
  });
});
