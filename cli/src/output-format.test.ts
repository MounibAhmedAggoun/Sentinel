import { describe, expect, it } from 'vitest';
import { OUTPUT_FORMATS, parseFormat } from './output-format.js';

describe('parseFormat', () => {
  it.each(OUTPUT_FORMATS)('accepts %s', (name) => {
    expect(parseFormat(name)).toEqual({ ok: true, format: name });
  });

  it.each(['', 'json', 'HTML', 'Markdown', ' table', 'table ', 'md', 'sarif', 'junit'])(
    'rejects %j',
    (raw) => {
      expect(parseFormat(raw).ok).toBe(false);
    },
  );

  it('names the valid formats in the error', () => {
    const result = parseFormat('nope');

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('format must be one of: table, markdown, html');
  });
});
