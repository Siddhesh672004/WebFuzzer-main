import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.js'],
    testTimeout: 20000,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.js'],
      // index.js is process bootstrap; queue/* needs a live Redis (covered by
      // integration runs, not unit tests).
      exclude: ['src/index.js', 'src/queue/**'],
    },
  },
});
