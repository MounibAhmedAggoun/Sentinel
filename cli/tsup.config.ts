import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  platform: 'node',
  target: 'node22',
  outDir: 'dist',
  clean: true,
  sourcemap: true,
  // The workspace packages are private and cannot be installed from npm,
  // so their code is bundled into the CLI. Third-party packages stay external.
  noExternal: ['@sentinel/core', '@sentinel/scanner'],
});
