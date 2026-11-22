/**
 * Shared MSW server for service-layer tests.
 *
 * The 22 API service modules had no tests: everything they do — unwrapping `response.data`,
 * building query strings, surfacing errors — was only ever exercised by clicking the app.
 * MSW intercepts at the network layer, so these run against the real `apiClient` including
 * its auth and 401 interceptors, rather than a hand-rolled axios stub that would prove
 * nothing about the interceptors.
 *
 * Register per-test handlers with `server.use(...)`; `onUnhandledRequest: 'error'` means a
 * request to a URL no handler matches fails the test rather than silently hanging, which is
 * what turns a wrong path (the #630 class) into a visible failure here too.
 */
import { http, HttpResponse } from 'msw'
import { setupServer } from 'msw/node'

/**
 * Defaults for requests many pages make in passing, so a test of one page doesn't need to know.
 * A test can still override them with `server.use(...)`.
 */
const defaults = [
  // The Suricata ruleset note (#600) appears beside alerts on several pages.
  http.get('*/system/suricata', () =>
    HttpResponse.json({
      engineVersion: '1:6.0.4-3',
      source: 'built-in',
      rulesetDate: '2026-11-08',
      ageDays: 1,
      stale: false,
      staleAfterDays: 30,
      ruleCount: 50000,
      importDir: '/var/lib/tracepcap/suricata-rules',
      importError: null,
    })
  ),
]

export const server = setupServer(...defaults)

/** Absolute URL for a version-agnostic endpoint path, matching what apiClient produces. */
export function apiUrl(path: string): string {
  return `*/api/v1${path}`
}
