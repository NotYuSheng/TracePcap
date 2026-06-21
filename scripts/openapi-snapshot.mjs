#!/usr/bin/env node
/*
 * OpenAPI schema-drift snapshot.
 *
 * Fetches the live OpenAPI spec, canonicalizes it (sorted keys, env-specific
 * `servers` stripped), and writes it to openapi/baseline.json.
 *
 * Usage:
 *   1. Bring the stack up:  docker compose up -d --build
 *   2. Regenerate baseline: node scripts/openapi-snapshot.mjs
 *   3. Commit openapi/baseline.json
 *
 * CI runs this and then `git diff --exit-code openapi/baseline.json`, so any
 * unintended change to the API contract fails the build. Intended changes are
 * accepted by regenerating and committing the baseline.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SPEC_URL = process.env.OPENAPI_URL || 'http://localhost:8888/v3/api-docs';
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BASELINE = path.join(repoRoot, 'openapi', 'baseline.json');

/** Recursively sort object keys so JSON serialization is stable across runs. */
function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.keys(value)
      .sort()
      .reduce((acc, key) => {
        acc[key] = canonicalize(value[key]);
        return acc;
      }, {});
  }
  return value;
}

const res = await fetch(SPEC_URL);
if (!res.ok) {
  console.error(`Failed to fetch OpenAPI spec from ${SPEC_URL}: HTTP ${res.status}`);
  process.exit(2);
}

const spec = await res.json();
// `servers` carries the request host/port, which differs per environment.
delete spec.servers;

const canonical = JSON.stringify(canonicalize(spec), null, 2) + '\n';
fs.mkdirSync(path.dirname(BASELINE), { recursive: true });
fs.writeFileSync(BASELINE, canonical);

const pathCount = Object.keys(spec.paths ?? {}).length;
console.log(`Wrote ${path.relative(repoRoot, BASELINE)} (${pathCount} paths).`);
