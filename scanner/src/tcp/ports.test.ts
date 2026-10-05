import { describe, expect, it } from 'vitest';
import { ALLOWED_PORTS, DEFAULT_PORTS, parsePorts } from './ports.js';

describe('DEFAULT_PORTS', () => {
  it('are all on the allowlist', () => {
    for (const port of DEFAULT_PORTS) {
      expect(ALLOWED_PORTS.has(port)).toBe(true);
    }
  });
});

describe('parsePorts', () => {
  it('parses a comma-separated list', () => {
    expect(parsePorts('80,443,8080')).toEqual({ ok: true, ports: [80, 443, 8080] });
  });

  it('trims spaces', () => {
    expect(parsePorts(' 80 , 443 ')).toEqual({ ok: true, ports: [80, 443] });
  });

  it('removes duplicates', () => {
    expect(parsePorts('80,80,443')).toEqual({ ok: true, ports: [80, 443] });
  });

  it.each(['', ' ', '80,', ',80', 'abc', '80;443', '80-90', '-1', '1.5', '0x50', '123456'])(
    'rejects malformed input %j',
    (input) => {
      expect(parsePorts(input).ok).toBe(false);
    },
  );

  it.each(['1', '9999', '65535', '0', '81'])('rejects a port not on the allowlist: %s', (input) => {
    expect(parsePorts(input).ok).toBe(false);
  });

  it('rejects the whole list if one port is not allowed', () => {
    expect(parsePorts('80,9999').ok).toBe(false);
  });
});
