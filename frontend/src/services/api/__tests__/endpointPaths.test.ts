import { describe, expect, it } from 'vitest';

// The backend's committed route snapshot, at the repo root — outside the frontend package.
// Imported rather than read through node:fs so this file needs no Node types: adding those to the
// test tsconfig leaks them into the browser sources tests import (setTimeout starts returning
// NodeJS.Timeout), producing errors in app code that is perfectly correct.
import baseline from '../../../../../openapi/baseline.json';
import { API_URL_PREFIX, directApiUrl } from '../directUrl';
import {
  API_ENDPOINTS,
  INSIGHTS_ENDPOINTS,
  MONITOR_ENDPOINTS,
  SUBNET_ENDPOINTS,
} from '../endpoints';

/**
 * Guards every frontend endpoint path against the backend's OpenAPI contract.
 *
 * The frontend and backend agree on URLs only by convention, so a path that no controller serves
 * fails silently at runtime — a 404 the user sees as a broken button. Extracted-file downloads
 * shipped broken for exactly this reason: the URL omitted the `/api/v1` version segment (nginx
 * proxies `/api/` to the backend with no rewrite), so every download 404'd.
 *
 * `openapi/baseline.json` is the committed snapshot of the backend's routes, already enforced in CI
 * — this test makes the frontend answer to it too.
 */

/**
 * Collapses `{anything}` to `{}` so path-parameter *names* may differ across the stack, and drops
 * the query string. Note the limitation that follows: this checks the *path* only, so a wrong
 * query parameter still passes.
 */
function normalize(path: string): string {
  return decodeURIComponent(path)
    .split('?')[0]
    .replace(/\{[^}]*\}/g, '{}')
    .replace(/\/$/, '');
}

const backendPaths = new Set(Object.keys(baseline.paths).map(normalize));

/** An entry in one of the endpoint maps: a fixed path, or a builder that takes path parameters. */
type EndpointValue = string | ((...args: never[]) => string);

/** Reads a builder's parameter names so each can be filled with an OpenAPI-style `{placeholder}`. */
function parameterNames(fn: (...args: never[]) => string): string[] {
  const source = fn.toString();
  const params = source.slice(source.indexOf('(') + 1, source.indexOf(')'));
  return params
    .split(',')
    .map(p => p.split(/[:=]/)[0].trim())
    .filter(Boolean);
}

/** Renders an endpoint entry as a templated path (`/files/{fileId}`), whatever its arity. */
function templatize(value: EndpointValue): string {
  if (typeof value === 'string') return value;
  const args = parameterNames(value).map(name => `{${name}}`);
  return value(...(args as never[]));
}

/**
 * Escape hatch for endpoints the backend genuinely does not serve yet. **Intentionally empty** —
 * every path in `endpoints.ts` currently resolves to a real route, and the aim is to keep it that
 * way, so an addition here should be rare and argued for.
 *
 * Never add an entry to silence a mismatch on a live call site — fix the path instead. The value is
 * the reason for the exemption. Entries are themselves checked below: one whose route later ships
 * fails the suite, so the list cannot quietly outlive the problem.
 */
const KNOWN_MISSING_ROUTES: Record<string, string> = {};

const ENDPOINT_MAPS = {
  API_ENDPOINTS,
  MONITOR_ENDPOINTS,
  SUBNET_ENDPOINTS,
  INSIGHTS_ENDPOINTS,
};

describe('endpoint paths match the backend OpenAPI contract', () => {
  const cases = Object.entries(ENDPOINT_MAPS).flatMap(([mapName, map]) =>
    Object.entries(map)
      .filter(([key]) => !(key in KNOWN_MISSING_ROUTES))
      .map(([key, value]) => [`${mapName}.${key}`, value] as const)
  );

  it('has endpoints to check', () => {
    expect(cases.length).toBeGreaterThan(50);
    expect(backendPaths.size).toBeGreaterThan(50);
  });

  it.each(cases)('%s resolves to a real backend route', (_name, value) => {
    // Endpoint maps hold version-agnostic paths; apiClient's baseURL supplies the prefix.
    const path = normalize(`${API_URL_PREFIX}${templatize(value)}`);
    expect(backendPaths).toContain(path);
  });

  it('exempts only endpoints that are still absent from the contract', () => {
    // Stops the exemption list outliving the problem. An entry goes stale two ways: the endpoint is
    // deleted from endpoints.ts, or the backend grows the route. The second matters more — a
    // silently-kept exemption means that endpoint is never contract-checked again.
    const entries = new Map<string, EndpointValue>(
      Object.values(ENDPOINT_MAPS).flatMap(map => Object.entries(map) as [string, EndpointValue][])
    );
    for (const key of Object.keys(KNOWN_MISSING_ROUTES)) {
      const value = entries.get(key);
      expect(value, `${key} is exempted but no longer exists — drop it`).toBeDefined();

      const path = normalize(`${API_URL_PREFIX}${templatize(value!)}`);
      expect(
        backendPaths,
        `${key} now resolves to a real backend route (${path}) — drop its exemption so it is checked`
      ).not.toContain(path);
    }
  });
});

describe('directApiUrl', () => {
  it('carries the version segment that apiClient would otherwise supply', () => {
    expect(directApiUrl('/files/abc/extractions/def/download')).toBe(
      '/api/v1/files/abc/extractions/def/download'
    );
  });

  it('produces the same prefix the backend actually serves', () => {
    // Anchors down the whole guard: if API_PREFIX moves in WebConfig, the baseline changes and
    // this fails, rather than every direct-navigation URL silently 404ing.
    for (const path of backendPaths) {
      expect(path.startsWith(`${API_URL_PREFIX}/`)).toBe(true);
    }
  });
});
