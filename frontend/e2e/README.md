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

## Demo recording

`demo.spec.ts` is not a test — it drives the walkthrough recorded for the README
GIF (`sample-files/TracePcap-Demo.gif`). It follows the **Office Audit scenario**
from `docs/sample-files.rst`: eight weekly captures of an office network, where
policy violations escalate and then subside after an audit notice.

It is **opt-in**: the `demo` project only registers when `DEMO=1`, so a normal
`npm run test:e2e` doesn't record video or wait out its pacing.

### Record against an empty stack

The demo seeds its own data (uploads the eight `sample-files/monitor_large/`
captures, creates the network, adds snapshots) and expects nothing else to be
there. Record against a fresh stack:

```bash
docker compose down -v        # ⚠️ destroys all uploaded pcaps and monitor data
docker compose up -d
scripts/record-demo.sh        # records, then encodes over the README GIF
```

This isn't fussiness. Node roles are keyed by **`file_id`, not `network_id`**
(`node_roles` has no network column), so any network sharing a capture sees and
writes the same role labels. A stack with existing data will show *its* labels in
the GIF, and the recording will write labels back into files other networks use.
An empty stack is the only way the recording is both reproducible and
non-destructive.

The first run analyses all eight captures (a few minutes). Later runs reuse them.

Record without encoding (writes a WebM under `test-results/`):

```bash
npm run demo:record
```

The spec deletes any existing copy of the fixture first, so each run records a
genuine first upload rather than the dedup ("Open existing") path.

Tuning knobs on `record-demo.sh`: `DEMO_WIDTH` (default 800), `DEMO_FPS` (10),
`DEMO_COLORS` (96) — these produce ~3MB, roughly GitHub's comfortable ceiling.
Pacing lives in the `BEAT`/`READ` constants in the spec, and it dominates size:
the GIF costs ~100KB per second of runtime, so trimming holds beats tuning the
encoder. Raising width/fps/colors grows the file fast — check the printed size.

When the UI changes, the spec's selectors are what break — tab labels are
matched by visible text, so renaming a tab fails the recording loudly rather
than silently omitting it.
