# TracePcap — Claude Guidelines

## UI Components

**Always use SGDS components first.** Before building a custom UI component, check if `@govtechsg/sgds-react` already provides it. The package is installed and its global CSS is imported via `src/assets/styles/index.css`.

Current SGDS usage: `Container`, `Row`, `Col`, `Card`, `Modal`, `Pagination`.

Only build a custom component if SGDS has no equivalent.

### Popups & info affordances

- **Explainer / help content behind a `bi bi-info-circle`** must open an **SGDS `Modal`** (or, for a small inline hint, a click-toggled help block) — never rely on a native `title=` tooltip, which is unreliable and inconsistent across the app. Make the trigger a real `<button>` (with an `aria-label` and the icon `aria-hidden`) so it is focusable and keyboard-activatable; if an element genuinely cannot be a button, it needs `role="button"` **plus** `tabIndex={0}` and Enter/Space key handling — `role="button"` with only `cursor: pointer` is not clickable for keyboard users.
- **Forms that create/edit a thing** (add evidence, override a label, add a snapshot, change a setting) open in the **right-hand drawer**, `SideDrawer` from `@components/common/SideDrawer` (`wide` for tables or several columns), not a centred modal and not an inline expanding panel. Put Save/Cancel in its `footer`; a `<form>` goes inside the body with an `id`, and the submit button names it with `form=`. Panels you read beside the page (host details, "How we got here", "Every category", a subnet, Manage PCAPs, a file preview) open in the drawer too. Centred SGDS `Modal`s are only for diagrams and the tracer (they need the width; the heatmap goes fullscreen), explainers behind an info icon, and yes/no confirmations ("Delete rule?").
- Keep the copy inside these modals task-oriented: say what the thing is and how to act on it (e.g. "click a badge to inspect it and add evidence").
- **Escape must close exactly one popup — the topmost one.** SGDS `Modal`s get this for free, so always wire `onHide` (leave it unwired only to deliberately block dismissal, e.g. mid-upload). Any popup that is *not* an SGDS `Modal` — an overlay panel, a portalled popover, a CSS-fullscreen mode — must call `useEscapeLayer(onClose, { ref })` from `@utils/useEscapeLayer` instead of installing its own `keydown` listener; the shared stack is what keeps one press from closing two layers.
- **Click-toggled info/help popovers** use `EscapableOverlayTrigger` from `@components/common/EscapableOverlayTrigger` — same props as SGDS `OverlayTrigger`, but it owns `show` and joins the Escape stack. Never `OverlayTrigger … rootClose`: inside a `Modal`, one Escape closes both. Give the `Popover` an `id` (it locates the layer by it).
- **The popover itself is `InfoPopover`** from `@components/common/InfoPopover`: a small `kind` label ("How it works", "How it's measured"), a `title`, the note, and a footer with its `source` and a `docs` page link. Every SGDS popover already gets the card style (rounded, shadow, no grey title bar) from `sgds-overrides.css`; use `InfoPopover` for any explainer so they all read the same.

## Shared Concepts

Some concepts have **one definition and one way in**. Before writing a helper that formats, counts, or classifies, look here and use the owner. The second module that needs something moves it into `common/` (backend) or `utils/` (frontend); it doesn't get a private copy.

| Concept | Backend | Frontend |
|---|---|---|
| Is this address inside the network | `LocalityRules` from `KnowledgeContext.locality()` / `ScanContext.locality()` / `LocalityPolicy` (custom ranges first). Never `IpLocality.isLocal` directly: only `common/net`, the policy and GeoIP may | `isPrivateIp` (custom ranges) / `isRfc1918` in `utils/ipClassification.ts` |
| Is this a real host / unspecified / a filled-in address field | `IpLocality.isHostAddress` / `isUnspecified` / `isAssigned` | `isHostAddress` / `isUnspecified` in `utils/ipClassification.ts` |
| Bytes, lengths of time, counted nouns | `common/text/Humanize` (`bytes`, `span`, `plural`) | `utils/formatters` (`formatBytes`, `formatSpan`, `formatDuration`, `formatNumber`) |
| A CIDR typed into settings | `common/net/Cidr.normalise` (bare IP → /32, host bits zeroed, literals only) | — (the backend validates) |
| Is this address inside a CIDR (IPv4 and IPv6) | `common/net/CidrBlock.contains`; in SQL `ip_inet(col) <<= CAST(? AS inet)` | `ipInCidr` in `utils/ipClassification.ts` |
| Reading, writing, sorting an address | `Cidr.addressBytes` / `Cidr.formatAddress` (RFC 5952) | `parseIp` / `formatIp` / `networkOf` / `compareIps` in `utils/ipClassification.ts` |
| MAC addresses | `common/net/MacAddress` | — |
| Well-known ports | `common/net/ServicePorts` | `utils/portUtils.ts` |
| Severity colours | — | `utils/severityColors.ts` |

Three checks hold this in place; when you add a shared concept, add it to the table **and** to a check, or it erodes:

- `scripts/check_shared_vocabulary.py`: a concept's literals (address ranges, the byte and duration unit ladders) appear only in its owner.
- `scripts/check_duplicate_helpers.py`: a concept-named helper (`format*`, `plural`, `pct`, `is*Local*`, `bytes`, `duration`, `severity*`, …) is defined in one file per side. Today's duplicates are a baseline that **may only shrink**: fix one, delete its line.
- `SharedConceptTest` (ArchUnit): callers go through the entry point, not around it.

**In code review**, a new helper that repeats a concept in this table is a finding, even when it's correct today: that's how five "is this local" helpers came to disagree (#694, #1338).

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
  - **Every LLM action in the app runs this way** (story, insights, snapshot insights, role and subnet-label suggestions, the tracer's packet explanations). Do the cheap checks before queueing (a subnet with no members fails at once with 422, not after waiting its turn), and answer what needs no model time at once with `AiJobService.finished(…)` (cached explanations) rather than queueing it. The legacy synchronous endpoints (`POST /stories`, `POST /monitor/networks/{id}/insights` and `…/snapshots/{snapshotId}/insights`, `POST /node-roles/suggest` and `/suggest-preview`, `POST /subnets/{id}/suggest-label`, `POST /tracer/{conversationId}/explanations`, `POST /filter/{fileId}/generate`) stay for API clients only; the app doesn't call them, and new code mustn't.
- **OpenAPI**: every controller has a `@Tag`, every method an `@Operation`. Swagger UI at `/swagger-ui/index.html` (disabled in prod).

## Offline Requirement

This app must function fully offline (no external API calls at runtime). Keep this in mind for any new features:

- **GeoIP**: **DB-IP Lite MMDB** (bundled in the Docker image) by default, with no outbound call. `ipinfo.io` is opt-in only (`GEO_FORCE_OFFLINE=false`), and then used when reachable with the MMDB as fallback. Keep `GEO_FORCE_OFFLINE` defaulting to `true` everywhere. Implemented in `GeoIpService.java` via `com.maxmind.geoip2`. Do not add any other external geo APIs.
- **Maps**: Use static SVG/GeoJSON bundled in the frontend — no tile servers (OpenStreetMap etc.).
- **LLM**: Already configurable via `LLM_BASE_URL` env var pointing to a local inference server (e.g. LM Studio, Ollama).
