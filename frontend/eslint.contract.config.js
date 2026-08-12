// Blocking lint config: the API-seam rules only.
//
// `npm run lint:contract`, run by lint-contract.yml on every PR. Deliberately narrower
// than eslint.config.js: it enforces the rules that guard the frontend<->backend contract
// and nothing else, so it is green today and can block merges from day one.
//
// The full rule set stays advisory until the pre-existing react-hooks/TypeScript errors
// are cleared, at which point this file folds back into eslint.config.js (#659).

import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import { defineConfig, globalIgnores } from 'eslint/config'
import tseslint from 'typescript-eslint'
import { contractRuleExemptions, noHardCodedApiUrls } from './eslint.contract.js'

export default defineConfig([
  globalIgnores([
    'dist',
    // Generated build/report output. Flat config does not read .gitignore, so these must be
    // listed or ESLint walks into the coverage HTML report's own bundled scripts (#659).
    'coverage',
    'playwright-report',
    'test-results',
  ]),
  {
    files: ['**/*.{ts,tsx}'],
    // Parser only — no `extends`, so none of the recommended rule sets come along and the
    // job reports contract violations exclusively. The plugins are still registered (without
    // enabling their rules) because source files carry inline `eslint-disable` comments for
    // them, and an unregistered rule name is itself an error.
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
      parser: tseslint.parser,
    },
    plugins: {
      '@typescript-eslint': tseslint.plugin,
      'react-hooks': reactHooks,
    },
    // Those plugins' rules are registered but not enabled, so every inline disable comment
    // for them looks unused here. That is expected, not a finding — eslint.config.js is
    // where unused directives are worth reporting.
    linterOptions: {
      reportUnusedDisableDirectives: 'off',
    },
    rules: {
      'no-restricted-syntax': noHardCodedApiUrls,
    },
  },
  {
    files: contractRuleExemptions,
    rules: { 'no-restricted-syntax': 'off' },
  },
])
