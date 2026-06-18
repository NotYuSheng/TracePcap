# E2E smoke tests

Playwright tests that drive the real app in a browser. They guard against
runtime-only regressions that type-checking and builds miss — notably the
React 19 issue where SGDS `Alert` rendered `null` and error states showed a
blank screen instead of a message (issue #384).

## Run locally

1. Bring up the stack:
   ```bash
   docker compose up -d --build
   ```
2. From `frontend/`:
   ```bash
   npm ci
   npx playwright install chromium
   npm run test:e2e
   ```

The tests target `http://localhost:8888` by default; override with
`E2E_BASE_URL`. The LLM-error tests force the `502` response via Playwright
route interception, so they do not require a (un)reachable LLM.

## What's covered

- `smoke.spec.ts` — the app loads and primary navigation renders.
- `llm-error.spec.ts` — Story and Filter Generator show a visible error alert
  (not a blank container) when generation returns `502`.
