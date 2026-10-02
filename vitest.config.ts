import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['{core,scanner,cli,api}/{src,test}/**/*.test.ts'],
    passWithNoTests: true,
  },
});