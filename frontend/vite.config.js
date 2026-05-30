import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Vite config. Dev server proxies /api → backend so the SPA and API share an
// origin in development (no CORS friction, cookies just work). Production build
// is small and tree-shaken; vendor libs are split into manual chunks so the
// Verify page doesn't pull charts/animations it never uses.

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: process.env.VITE_API_BASE || 'http://localhost:4000',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          react: ['react', 'react-dom', 'react-router-dom'],
          query: ['@tanstack/react-query'],
          charts: ['recharts'],
          motion: ['framer-motion'],
        },
      },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./test/setup.js'],
    include: ['test/**/*.test.{js,jsx}'],
    css: false,
  },
});
