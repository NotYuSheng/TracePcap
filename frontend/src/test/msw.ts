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
import { setupServer } from 'msw/node'

export const server = setupServer()

/** Absolute URL for a version-agnostic endpoint path, matching what apiClient produces. */
export function apiUrl(path: string): string {
  return `*/api/v1${path}`
}
