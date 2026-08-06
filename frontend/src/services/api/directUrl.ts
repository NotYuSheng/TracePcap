/**
 * Version prefix for API URLs the **browser** fetches directly — anchor `href`, `<img>`/`<video>`
 * `src`, `window.open` — rather than through `apiClient`.
 *
 * These URLs bypass axios, so they do not inherit `apiClient`'s configured `baseURL` and must carry
 * the version segment themselves. nginx proxies `/api/` to the backend **verbatim, with no
 * rewrite**, so a versionless path such as `/api/files/…` matches no handler and 404s — which the
 * browser surfaces as "File wasn't available on site" on a download.
 *
 * Keep every such URL going through {@link directApiUrl} so the prefix is defined in exactly one
 * place. `endpointPaths.test.ts` validates the result against `openapi/baseline.json`.
 */
export const API_URL_PREFIX = '/api/v1';

/**
 * Builds a same-origin URL for direct browser navigation from a version-agnostic endpoint path.
 *
 * @param path version-agnostic path beginning with `/`, e.g. `/files/{id}/extractions/{id}/download`
 */
export function directApiUrl(path: string): string {
  return `${API_URL_PREFIX}${path}`;
}
