import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.js'],
    testTimeout: 20000, // mongodb-memory-server can be slow on first download
    // Force the json mail transport at config-load time so the auth controller
    // returns devOtp for tests (config is frozen on import).
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
