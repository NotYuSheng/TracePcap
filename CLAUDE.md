# TracePcap — Claude Guidelines

## UI Components

**Always use SGDS components first.** Before building a custom UI component, check if `@govtechsg/sgds-react` already provides it. The package is installed and its global CSS is imported via `src/assets/styles/index.css`.

Current SGDS usage: `Container`, `Row`, `Col`, `Card`, `Modal`, `Pagination`.

Only build a custom component if SGDS has no equivalent.

### Popups & info affordances

- **Explainer / help content behind a `bi bi-info-circle`** must open an **SGDS `Modal`** (or, for a small inline hint, a click-toggled help block) — never rely on a native `title=` tooltip, which is unreliable and inconsistent across the app. Make the trigger a real `<button>` (with an `aria-label` and the icon `aria-hidden`) so it is focusable and keyboard-activatable; if an element genuinely cannot be a button, it needs `role="button"` **plus** `tabIndex={0}` and Enter/Space key handling — `role="button"` with only `cursor: pointer` is not clickable for keyboard users.
- **Forms that create/edit a thing** (add evidence, override a label, add a snapshot) belong in an **SGDS `Modal`**, not an inline expanding panel — keep the surface uncluttered and the action focused.
- Keep the copy inside these modals task-oriented: say what the thing is and how to act on it (e.g. "click a badge to inspect it and add evidence").
- **Escape must close exactly one popup — the topmost one.** SGDS `Modal`s get this for free, so always wire `onHide` (leave it unwired only to deliberately block dismissal, e.g. mid-upload). Any popup that is *not* an SGDS `Modal` — an overlay panel, a portalled popover, a CSS-fullscreen mode — must call `useEscapeLayer(onClose, { ref })` from `@utils/useEscapeLayer` instead of installing its own `keydown` listener; the shared stack is what keeps one press from closing two layers.
- **Click-toggled info/help popovers** use `EscapableOverlayTrigger` from `@components/common/EscapableOverlayTrigger` — same props as SGDS `OverlayTrigger`, but it owns `show` and joins the Escape stack. Never `OverlayTrigger … rootClose`: inside a `Modal`, one Escape closes both. Give the `Popover` an `id` (it locates the layer by it).
- **The popover itself is `InfoPopover`** from `@components/common/InfoPopover`: a small `kind` label ("How it works", "How it's measured"), a `title`, the note, and a footer with its `source` and a `docs` page link. Every SGDS popover already gets the card style (rounded, shadow, no grey title bar) from `sgds-overrides.css`; use `InfoPopover` for any explainer so they all read the same.

## Branching

- `dev` is the integration branch; `main` is the release branch and remains the repo default.
- **`gh pr create` defaults to `main`, which is wrong for everyday work — always pass
  `--base dev` explicitly.**
- Branch from `dev`, and open PRs **against `dev`**. Never open a PR against `main` except the
  periodic `dev` -> `main` release PR, and never commit to `main` directly.
- PRs into `dev` run the full test gates and must be green to merge. The long jobs (system, backend, frontend, arm64) don't re-run on pushes to `dev`, only on the release PR and on `main`.
- See CONTRIBUTING.md for what runs where and how to cut a release.


## Stack

- **Frontend**: React + TypeScript + Vite, served via nginx
- **Backend**: Spring Boot (Java)
- **DB**: PostgreSQL with Flyway migrations
- **Storage**: MinIO
- **Build**: Docker Compose — run `docker compose build` to build, `docker compose up -d` to start
- **After every change**: run `scripts/rebuild.sh` to rebuild and restart all services. It builds one image at a time; `docker compose up -d --build` builds them in parallel and, next to a running stack and a `mvn verify`, has frozen this 15 GB machine. Never run it alongside `mvn verify` or the frontend test suite.
- **Before any heavy job** (image builds, `mvn verify`/test runs, the full frontend suite, Playwright recordings) run `scripts/mem-guard.sh "<job>"`: it refuses when under 4 GB is available or swap is over 40% used. `rebuild.sh` and `record-demo.sh` call it themselves. On 2026-11-16 a recording started with swap 59% full froze this machine (disk thrash, hard reset). Run heavy jobs one at a time; locally vitest uses at most 3 workers.

## API Conventions

All REST endpoints follow these rules. Match them when adding or changing endpoints.

- **Versioning**: every endpoint lives under `/api/v1`. The prefix is applied **centrally** in `WebConfig.configurePathMatch` (`API_PREFIX` constant) — controllers declare **version-agnostic** paths (e.g. `@RequestMapping("/files")`, not `/api/v1/files`). To cut a new version, bump `API_PREFIX` in one place. The frontend base path lives in `client.ts` / the `VITE_API_BASE_URL` build arg.
- **Resource naming**: **plural kebab-case nouns** for collections (`/files`, `/node-roles`, `/custom-private-ranges`). Singular only for true singletons/namespaces (`/system`).
- **HTTP methods & status**: `GET` (read), `POST` (create → **201**), `PUT`/`PATCH` (update), `DELETE` (→ **204**). Put the resource id in the **path**, not the body/query.
- **Custom methods** (computations that don't map to CRUD — e.g. detect, suggest, generate): prefer reframing as resource creation (`POST /stories` instead of `POST /story/generate/{id}`). When it genuinely isn't a resource, use an **id-first action segment**: `POST /filter/{fileId}/generate`, not `POST /filter/generate/{fileId}`.
- **Pagination**: return `PagedResponse<T>` (`data`, `page`, `pageSize`, `total`, `totalPages`), **1-indexed** `page` + `pageSize` query params. Do not serialize Spring's `Page` directly.
- **Errors**: never hand-build error bodies — throw, and let `GlobalExceptionHandler` map to the shared `ErrorResponse` envelope. `@Valid`/`@Validated` failures return **400** with a `validationErrors` map.
- **DTOs only**: controllers return DTOs, never JPA entities.
- **Slow work runs in the background — never hold a request open on it.** An endpoint answers in a few seconds. Anything that calls the LLM (minutes on a local model), or otherwise can take longer, is *created and then checked on*: `POST` returns **201** at once with a job, the client polls, and the result outlives the page that asked. LLM work goes through `AiJobService` (`common/aijob`): one job at a time for the model, so jobs queue instead of competing, and asking again while one waits returns that job. Start it from the resource's own `…-jobs` collection (`POST /files/{id}/story-jobs`, `POST /monitor/networks/{id}/insight-jobs`); clients check it at `GET /ai-jobs/{id}`, and the header's AI chip lists it. Whole-capture processing uses the analysis executor and a status on the resource (upload, re-analysis). Two deliberate exceptions: the capture chat (its own `chat-turns`, which skip the queue because someone is waiting on them) and `POST /system/llm/test` (seconds, and you want the answer right there).
  - **Still synchronous, to move onto jobs:** `POST /node-roles/suggest` and `/suggest-preview`, `POST /subnets/{id}/suggest-label`, `POST /tracer/{conversationId}/explanations`, `POST /monitor/networks/{id}/snapshots/{snapshotId}/insights`, and the legacy `POST /stories` and `POST /monitor/networks/{id}/insights` (kept for API clients; the app no longer uses them). `POST /filter/{fileId}/generate` is unused since the Filter Generator folded into the chat.
- **OpenAPI**: every controller has a `@Tag`, every method an `@Operation`. Swagger UI at `/swagger-ui/index.html` (disabled in prod).

## Offline Requirement

This app must function fully offline (no external API calls at runtime). Keep this in mind for any new features:

- **GeoIP**: Uses a hybrid strategy — `ipinfo.io` when internet is reachable, **DB-IP Lite MMDB** (bundled in the Docker image) as automatic offline fallback. Implemented in `GeoIpService.java` via `com.maxmind.geoip2`. Do not add any other external geo APIs.
- **Maps**: Use static SVG/GeoJSON bundled in the frontend — no tile servers (OpenStreetMap etc.).
- **LLM**: Already configurable via `LLM_BASE_URL` env var pointing to a local inference server (e.g. LM Studio, Ollama).
