import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import { defineConfig, globalIgnores } from 'eslint/config'
import {
  contractRuleExemptions,
  generatedOutputIgnores,
  noHardCodedApiUrls,
} from './eslint.contract.js'

export default defineConfig([
  globalIgnores(generatedOutputIgnores),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
    rules: {
      // Definition lives in eslint.contract.js so the blocking CI job (lint:contract)
      // enforces exactly this rule, with no chance of the two configs drifting.
      'no-restricted-syntax': noHardCodedApiUrls,
    },
  },
  {
    files: contractRuleExemptions,
    rules: { 'no-restricted-syntax': 'off' },
  },
])
