import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.js'],
    testTimeout: 30000,
    hookTimeout: 300000, // first run downloads MongoDB binary (~600MB)
    fileParallelism: false,
    setupFiles: ['./test/mongoSetup.js'],
    env: {
      MAIL_TRANSPORT: 'json',
    },
    coverage: {
      provider: 'v8',
      include: ['src/**/*.js'],
      exclude: ['src/server.js'], // lifecycle wiring, not unit-testable
    },
  },
});
