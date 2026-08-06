import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist']),
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
      // Hand-written "/api/..." URLs drift from the backend's routes: they skip both apiClient's
      // baseURL and the endpoints.ts map, so nothing checks them against the API contract. That is
      // how extracted-file downloads shipped pointing at "/api/files/..." — missing the /api/v1
      // version segment, 404ing on every click. Route direct-navigation URLs (anchor href, img/
      // video src) through directApiUrl(); everything else goes through apiClient.
      'no-restricted-syntax': [
        'error',
        {
          selector: 'Literal[value=/^\\u002Fapi(\\u002F|$)/]',
          message:
            'Do not hard-code /api URLs. Use apiClient (adds the base URL) or directApiUrl() from @/services/api/directUrl for URLs the browser fetches directly.',
        },
        {
          selector: 'TemplateElement[value.raw=/^\\u002Fapi(\\u002F|$)/]',
          message:
            'Do not hard-code /api URLs. Use apiClient (adds the base URL) or directApiUrl() from @/services/api/directUrl for URLs the browser fetches directly.',
        },
      ],
    },
  },
  {
    // directUrl.ts defines the prefix; the API tests and e2e specs assert on and intercept real
    // URLs; vite.config.ts's "/api" is a dev-proxy mount path, not a request URL.
    files: [
      'src/services/api/directUrl.ts',
      'src/services/api/__tests__/**',
      'e2e/**',
      'vite.config.ts',
    ],
    rules: { 'no-restricted-syntax': 'off' },
  },
])
