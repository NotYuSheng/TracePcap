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
      // SGDS's Alert renders nothing unless `show` is passed (it relies on defaultProps), so a
      // direct import silently hides error and notice messages. The wrapper sets the default.
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: '@govtechsg/sgds-react',
              importNames: ['Alert'],
              message: "Use Alert from '@components/common/Alert': SGDS's renders nothing without show.",
            },
          ],
        },
      ],
    },
  },
  {
    files: ['src/components/common/Alert/**'],
    rules: { 'no-restricted-imports': 'off' },
  },
  {
    files: contractRuleExemptions,
    rules: { 'no-restricted-syntax': 'off' },
  },
])
