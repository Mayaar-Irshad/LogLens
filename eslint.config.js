import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import tseslint from 'typescript-eslint';

/**
 * Security guardrails: log-derived data must never reach an HTML sink,
 * dynamic code evaluation, or persistent browser storage.
 */
const securityRules = {
  'no-eval': 'error',
  'no-implied-eval': 'off',
  '@typescript-eslint/no-implied-eval': 'error',
  'no-new-func': 'error',
  'no-script-url': 'error',
  'no-console': ['error', { allow: ['error'] }],
  'no-restricted-globals': [
    'error',
    { name: 'localStorage', message: 'LogLens must not persist data in localStorage.' },
    { name: 'sessionStorage', message: 'LogLens must not persist data in sessionStorage.' },
    { name: 'indexedDB', message: 'LogLens must not persist data in IndexedDB.' },
    { name: 'caches', message: 'LogLens must not persist data in Cache Storage.' },
    { name: 'fetch', message: 'LogLens must not make network requests with log data.' },
    { name: 'XMLHttpRequest', message: 'LogLens must not make network requests with log data.' },
  ],
  'no-restricted-properties': [
    'error',
    { property: 'innerHTML', message: 'Never write HTML from untrusted data.' },
    { property: 'outerHTML', message: 'Never write HTML from untrusted data.' },
    { property: 'insertAdjacentHTML', message: 'Never write HTML from untrusted data.' },
    { object: 'document', property: 'write', message: 'Never write HTML from untrusted data.' },
    { object: 'window', property: 'open', message: 'Do not navigate to log-derived URLs.' },
  ],
  'no-restricted-syntax': [
    'error',
    {
      selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
      message: 'dangerouslySetInnerHTML is forbidden in LogLens.',
    },
  ],
};

export default tseslint.config(
  { ignores: ['dist', 'coverage', 'node_modules', 'docs', '.taste-skill'] },
  {
    files: ['src/**/*.{ts,tsx}', 'tests/**/*.{ts,tsx}'],
    extends: [js.configs.recommended, ...tseslint.configs.recommendedTypeChecked],
    languageOptions: {
      ecmaVersion: 2022,
      globals: { ...globals.browser, ...globals.worker },
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...reactHooks.configs.flat.recommended.rules,
      'react-refresh/only-export-components': [
        'warn',
        { allowConstantExport: true, allowExportNames: ['useApp', 'useData'] },
      ],
      '@typescript-eslint/consistent-type-imports': 'error',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', ignoreRestSiblings: true },
      ],
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': [
        'error',
        { checksVoidReturn: { attributes: false } },
      ],
      eqeqeq: ['error', 'always'],
      ...securityRules,
    },
  },
  {
    files: ['tests/**/*.{ts,tsx}'],
    rules: {
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/unbound-method': 'off',
      // Asymmetric matchers such as expect.stringContaining() are typed as any.
      '@typescript-eslint/no-unsafe-assignment': 'off',
      'react-refresh/only-export-components': 'off',
    },
  },
  {
    files: ['vite.config.ts'],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: { globals: { ...globals.node } },
  },
  {
    files: ['*.config.js', 'scripts/**/*.{js,mjs}'],
    extends: [js.configs.recommended],
    languageOptions: { globals: { ...globals.node } },
  },
);
