import { describe, expect, it } from 'vitest';
import { targetSchema } from './validate.js';

describe('targetSchema', () => {
  it.each([
    'example.com',
    'sub.example.com',
    'EXAMPLE.com',
    'my-site.example.org',
    '8.8.8.8',
    '127.0.0.1',
    '2606:4700:4700::1111',
    '  example.com  ',
  ])('accepts %s', (input) => {
    expect(targetSchema.safeParse(input).success).toBe(true);
  });

  it.each([
    '',
    '   ',
    'http://example.com',
    'example.com/path',
    'example.com:8080',
    'exa mple.com',
    'example.com; rm -rf /',
    '$(whoami).example.com',
    '-example.com',
    'example..com',
    '2130706433',
    '0x7f000001',
    'a'.repeat(254),
  ])('rejects %j', (input) => {
    expect(targetSchema.safeParse(input).success).toBe(false);
  });
});
