import { describe, expect, it } from 'vitest';
import { SENTINEL_NAME } from './index.js';

describe('core', () => {
  it('exports the project name', () => {
    expect(SENTINEL_NAME).toBe('sentinel');
  });
});