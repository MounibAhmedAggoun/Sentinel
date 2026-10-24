import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { VERSION } from './version.js';

describe('VERSION', () => {
  it('matches the version in cli/package.json', () => {
    const packageJsonPath = fileURLToPath(new URL('../package.json', import.meta.url));
    const pkg = JSON.parse(readFileSync(packageJsonPath, 'utf8')) as { version: string };

    expect(VERSION).toBe(pkg.version);
  });

  it('looks like a semantic version', () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+/);
  });
});
