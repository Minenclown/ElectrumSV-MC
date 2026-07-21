import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/__tests__/setup.ts',
    css: false,
  },
  resolve: {
    alias: {
      // Avoid loading the real vite plugin (reads filesystem) in tests
      './src/local-token-plugin': '/dev/null',
    },
  },
});