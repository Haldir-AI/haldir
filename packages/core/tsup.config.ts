import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  sourcemap: true,
  // canonicalize 5 is ESM-only. Bundle it so the CJS build does not call
  // a missing default export through require().
  noExternal: ['canonicalize'],
});
