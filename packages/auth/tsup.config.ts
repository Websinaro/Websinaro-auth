import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'middleware/index': 'src/middleware/index.ts',
    'adapters/index': 'src/adapters/index.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  splitting: true,
  treeshake: true,
  sourcemap: true,
  clean: true,
  minify: false,
  target: 'es2022',
  platform: 'node',
  external: ['ioredis', '@prisma/client'],
  esbuildOptions(options) {
    options.conditions = ['module'];
  },
});
