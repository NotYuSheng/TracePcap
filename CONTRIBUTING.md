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
node scripts/openapi-snapshot.mjs # regenerate openapi/baseline.json
git add openapi/baseline.json     # commit it alongside your code change
```

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
