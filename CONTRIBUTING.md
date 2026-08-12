# Contributing to TracePcap

Thanks for contributing! This guide covers workflows that aren't obvious from the
code alone. For architecture and coding conventions (stack, UI components, REST
API rules, the offline requirement), see [`CLAUDE.md`](./CLAUDE.md).

## API Contract Workflow

The REST API has a committed contract snapshot at
[`openapi/baseline.json`](./openapi/baseline.json), generated from the live
OpenAPI spec by [`scripts/openapi-snapshot.mjs`](./scripts/openapi-snapshot.mjs).
CI fails any PR whose code produces a spec that differs from the committed
baseline, so the baseline must be regenerated and committed **in the same PR** as
the API change.

### When it applies

Regenerate the baseline whenever you add, change, or remove:

- a controller endpoint (path, method, parameters, status codes), or
- a request/response DTO (fields, types, validation constraints).

### The loop

The script reads the spec from the **running** app, so the stack must be up to
date with your change first:

```bash
docker compose up -d --build      # rebuild & start the stack with your change
# the backend takes a few seconds to boot — wait until it serves the spec
until curl -sf http://localhost:8888/v3/api-docs >/dev/null; do sleep 2; done
node scripts/openapi-snapshot.mjs # regenerate openapi/baseline.json
git add openapi/baseline.json     # commit it alongside your code change
```

(CI does the same readiness wait before running the script.)

### What CI enforces

[`.github/workflows/api-schema-drift.yml`](./.github/workflows/api-schema-drift.yml)
(the **OpenAPI contract snapshot** check) runs on PRs touching `backend/**`, the
snapshot script, the baseline, or the workflow itself. It builds the stack,
regenerates the spec, and fails if `openapi/baseline.json` has uncommitted drift.
If the check fails, run the loop above and commit the result.

### Gotchas

- **Keep controller method names unique.** springdoc derives each operation's
  `operationId` from the Java method name. A duplicate name (e.g. two `update()`
  methods across controllers) silently renames *another* endpoint's
  `operationId` and churns the contract. Prefer descriptive names like
  `updateExternalEvent`.
- **Validation is part of the contract.** Adding `@Valid` on a `@RequestBody`
  plus `@NotNull` / `@NotBlank` on DTO fields surfaces in the spec as `required`
  fields — expected, but it will show up in the baseline diff. (Per the API
  conventions in `CLAUDE.md`, prefer `@Valid` + `GlobalExceptionHandler` over
  hand-built error responses.)

## Test Coverage

Both suites report coverage. Neither **gates** on it yet — see
[#659](https://github.com/NotYuSheng/TracePcap/issues/659). The first job is a truthful
baseline; a threshold picked before anyone knows the real number just gets bypassed.

```bash
# Backend — JaCoCo, attached to `verify`
cd backend && mvn -B clean verify
#   HTML: backend/target/site/jacoco/index.html
#   CSV:  backend/target/site/jacoco/jacoco.csv

# Frontend — v8 via vitest
cd frontend && npm run test:coverage
#   HTML: frontend/coverage/index.html
```

CI prints a summary table on every PR (see the run's **Summary** tab) and uploads the
full HTML report as an artifact, retained 14 days.

### Baseline (Aug 2026)

| Suite | Metric | Coverage |
|---|---|---|
| Backend | Instructions | 19.41% |
| Backend | Branches | 12.24% |
| Frontend | Statements | 3.23% |
| Frontend | Branches | 2.28% |

Backend figures are 195 tests on `main`. An earlier revision of this table read 21.00% /
13.85%: that run was measured on a branch cut from an unmerged feature branch, so it counted
26 tests that are not on `main`. Measure baselines from `main`, not from whatever happens to
be checked out.

### What is excluded, and why

- **Backend**: the `TracePcapApplication` entry point, plus `**/entity/**` and `**/dto/**`.
  Those are data carriers — including them measures the mapper, not our logic. A
  `lombok.config` sets `lombok.addLombokGeneratedAnnotation = true` so JaCoCo skips
  generated getters/builders/`equals`; without it the figure measures Lombok.
- **Frontend**: `coverage.all = true` is deliberate. It counts every module under `src/`,
  not just the ones a test already imports — otherwise the untested majority of the app is
  simply absent from the report and the number flatters us. Only `src/assets/**` (bundled
  map geometry and icon tables), test scaffolding, and `main.tsx` are excluded.

### Generated API types

`frontend/src/services/api/generated/schema.d.ts` is generated from `openapi/baseline.json`
and **committed**. Regenerate it whenever the baseline changes:

```bash
cd frontend && npm run api:types
```

CI regenerates and diffs it (`test-frontend.yml`, which also triggers on `openapi/**`), so a
stale file fails the build. The generation is deterministic — byte-identical output for the
same baseline.

Use it instead of hand-writing an interface for a payload the backend already defines:

```ts
import type { Schema, ResponseOf } from '@/services/api/contract'

type Conversation = Schema<'ConversationResponse'>
type FilesPage = ResponseOf<'/api/v1/files', 'get'>
```

`endpointPaths.test.ts` proves every frontend URL resolves to a real route; that guards the
**URLs**. `contractConformance.test-d.ts` guards the **shapes** travelling over them — it has
no runtime body and fails by refusing to compile, so it is checked by `npm run typecheck:test`.
Add a case there whenever a frontend interface mirrors a backend DTO.

Note that `src/types/` still contains hand-written interfaces mirroring backend DTOs, several
of which have drifted (fields the backend no longer sends). Migrating each to `Schema<'...'>`
is tracked in #659 — prefer the generated type for anything new or touched.
