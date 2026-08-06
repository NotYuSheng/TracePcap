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

/** Collapses `{anything}` to `{}` so path-parameter *names* may differ across the stack. */
function normalize(path: string): string {
  return decodeURIComponent(path)
    .split('?')[0]
    .replace(/\{[^}]*\}/g, '{}')
    .replace(/\/$/, '');
}

const backendPaths = new Set(Object.keys(baseline.paths).map(normalize));

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
function templatize(value: string | ((...args: never[]) => string)): string {
  if (typeof value === 'string') return value;
  const args = parameterNames(value).map(name => `{${name}}`);
  return value(...(args as never[]));
}

/**
 * Pre-existing mismatches, exempted so this guard could be introduced without a wider cleanup.
 * Every one is currently **unreferenced** by any component, so none breaks a live feature — but
 * each is a loaded gun: wiring one up gives an instant 404.
 *
 * Do not add entries to silence a mismatch on a live call site — fix the path instead. Delete an
 * entry when the endpoint is either implemented or removed from `endpoints.ts`.
 */
const KNOWN_MISSING_ROUTES: Record<string, string> = {
  // Declared as "not yet implemented in backend" in endpoints.ts; no controller serves /timeline.
  TIMELINE_DATA: 'no backend route',
  TIMELINE_RANGE: 'no backend route',
  // No controller serves /analysis/{id}/five-ws or /kill-chain. analysisService.getFiveWs() and
  // getKillChain() exist but nothing calls them.
  FIVE_WS: 'no backend route; analysisService.getFiveWs() is uncalled',
  KILL_CHAIN: 'no backend route; analysisService.getKillChain() is uncalled',
  // Baselines hang off the network, not a snapshot: /monitor/networks/{id}/baseline/definitions
  // (see BASELINE_DEFINITIONS, which is correct). This entry is uncalled.
  SNAPSHOT_BASELINE: 'wrong shape; superseded by BASELINE_DEFINITIONS',
};

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
    // Stops the exemption list outliving the problem: once a route ships, its entry must go.
    const allKeys = new Set(Object.values(ENDPOINT_MAPS).flatMap(map => Object.keys(map)));
    for (const key of Object.keys(KNOWN_MISSING_ROUTES)) {
      expect(allKeys, `${key} is exempted but no longer exists — drop it`).toContain(key);
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
