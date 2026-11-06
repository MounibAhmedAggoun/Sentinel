import { describe, expect, it } from 'vitest';
import { parseTimeout } from './timeout.js';

describe('parseTimeout', () => {
  it('accepts whole seconds and returns milliseconds', () => {
    expect(parseTimeout('1')).toEqual({ ok: true, ms: 1000 });
    expect(parseTimeout('10')).toEqual({ ok: true, ms: 10_000 });
    expect(parseTimeout('60')).toEqual({ ok: true, ms: 60_000 });
  });

  it.each(['0', '61', '-5', '1.5', 'abc', '', '10s', ' 10', '1e1'])('rejects %j', (raw) => {
    expect(parseTimeout(raw).ok).toBe(false);
  });
});
