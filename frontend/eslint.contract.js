// Contract rules: the lint rules that guard the frontend<->backend API seam.
//
// Split out of eslint.config.js so CI can enforce *these* without also enforcing the
// full rule set. `lint-frontend.yml` is an auto-fixer that cannot fail a build, and the
// repo carries pre-existing react-hooks/TypeScript errors, so a blocking job over
// everything would be red from the first run and get switched off. These rules block
// today; the rest become blocking as the backlog clears (#659).

// Generated build/report output. Flat config does not read .gitignore, so these must be
// listed or ESLint walks into the coverage HTML report's own bundled scripts (#659).
// Shared for the same reason the rule is: two copies drift.
export const generatedOutputIgnores = ['dist', 'coverage', 'playwright-report', 'test-results']

const message =
  'Do not hard-code /api URLs. Use apiClient (adds the base URL) or directApiUrl() from ' +
  '@/services/api/directUrl for URLs the browser fetches directly.'

// Hand-written "/api/..." URLs drift from the backend's routes: they skip both apiClient's
// baseURL and the endpoints.ts map, so nothing checks them against the API contract. That is
// how extracted-file downloads shipped pointing at "/api/files/..." — missing the /api/v1
// version segment, 404ing on every click. Route direct-navigation URLs (anchor href, img/
// video src) through directApiUrl(); everything else goes through apiClient.
export const noHardCodedApiUrls = [
  'error',
  {
    selector: 'Literal[value=/^\\u002Fapi(\\u002F|$)/]',
    message,
  },
  {
    selector: 'TemplateElement[value.raw=/^\\u002Fapi(\\u002F|$)/]',
    message,
  },
]

// directUrl.ts defines the prefix; the API tests and e2e specs assert on and intercept real
// URLs; vite.config.ts's "/api" is a dev-proxy mount path, not a request URL. The generated
// schema is the contract itself — its "/api/v1/..." keys are the routes this rule checks
// hand-written URLs against, so exempting it is the point, not an escape hatch.
export const contractRuleExemptions = [
  'src/services/api/generated/**',
  'src/services/api/directUrl.ts',
  // Any test may assert on a real URL — that is how the rule's own subject gets verified.
  // Narrower than it looks: this exempts assertions, not production code, and a test that
  // hard-codes a wrong URL still fails endpointPaths.test.ts and its MSW handler.
  'src/**/__tests__/**',
  'e2e/**',
  'vite.config.ts',
]
