import { readFileSync } from 'node:fs';
import { defineConfig, type Plugin } from 'vitest/config';
import react from '@vitejs/plugin-react';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')) as {
  version: string;
};

/**
 * Production Content-Security-Policy. LogLens never needs to contact a network
 * origin at runtime, so `connect-src` is 'none' and every other fetch directive
 * is limited to the site's own origin. The policy is injected only into the
 * production build because Vite's dev server relies on inline scripts and a
 * websocket for hot module replacement.
 */
const PRODUCTION_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "worker-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'none'",
  "manifest-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
].join('; ');

function contentSecurityPolicy(): Plugin {
  return {
    name: 'loglens-csp',
    apply: 'build',
    transformIndexHtml(html) {
      return html.replace(
        '<!-- CSP -->',
        `<meta http-equiv="Content-Security-Policy" content="${PRODUCTION_CSP}" />`,
      );
    },
  };
}

// A relative base lets the static build work from any sub-path, including
// https://<user>.github.io/<repo>/, without rebuilding. BASE_PATH overrides it.
const base = process.env.BASE_PATH ?? './';

export default defineConfig({
  base,
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },
  plugins: [react(), contentSecurityPolicy()],
  worker: {
    format: 'es',
  },
  build: {
    target: 'es2022',
    // The polyfill uses fetch(), which the CSP (connect-src 'none') forbids; modern browsers support modulepreload natively.
    modulePreload: { polyfill: false },
    sourcemap: false,
    chunkSizeWarningLimit: 900,
  },
  test: {
    projects: [
      {
        extends: true,
        test: {
          name: 'unit',
          environment: 'node',
          include: ['tests/unit/**/*.test.ts', 'tests/integration/**/*.test.ts'],
        },
      },
      {
        extends: true,
        test: {
          name: 'components',
          environment: 'jsdom',
          include: ['tests/components/**/*.test.tsx'],
          setupFiles: ['tests/setup.ts'],
        },
      },
    ],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/main.tsx', 'src/**/*.d.ts', 'src/workers/analysis.worker.ts'],
      reporter: ['text-summary', 'text', 'html', 'json-summary'],
      thresholds: {
        'src/features/log-ingestion/**': { lines: 90 },
        'src/features/detection/**': { lines: 90 },
        'src/features/analytics/**': { lines: 90 },
      },
    },
  },
});
