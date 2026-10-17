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

## Branching

- `dev` is the integration branch; `main` is the release branch and remains the repo default.
- **`gh pr create` defaults to `main`, which is wrong for everyday work — always pass
  `--base dev` explicitly.**
- Branch from `dev`, and open PRs **against `dev`**. Never open a PR against `main` except the
  periodic `dev` -> `main` release PR, and never commit to `main` directly.
- `dev` runs the same gates as `main` and is expected to be green.
- See CONTRIBUTING.md for what runs where and how to cut a release.


## Stack

- **Frontend**: React + TypeScript + Vite, served via nginx
- **Backend**: Spring Boot (Java)
- **DB**: PostgreSQL with Flyway migrations
- **Storage**: MinIO
- **Build**: Docker Compose — run `docker compose build` to build, `docker compose up -d` to start
- **After every change**: run `docker compose up -d --build` to rebuild and restart all services

## API Conventions

All REST endpoints follow these rules. Match them when adding or changing endpoints.

- **Versioning**: every endpoint lives under `/api/v1`. The prefix is applied **centrally** in `WebConfig.configurePathMatch` (`API_PREFIX` constant) — controllers declare **version-agnostic** paths (e.g. `@RequestMapping("/files")`, not `/api/v1/files`). To cut a new version, bump `API_PREFIX` in one place. The frontend base path lives in `client.ts` / the `VITE_API_BASE_URL` build arg.
- **Resource naming**: **plural kebab-case nouns** for collections (`/files`, `/node-roles`, `/custom-private-ranges`). Singular only for true singletons/namespaces (`/system`).
- **HTTP methods & status**: `GET` (read), `POST` (create → **201**), `PUT`/`PATCH` (update), `DELETE` (→ **204**). Put the resource id in the **path**, not the body/query.
- **Custom methods** (computations that don't map to CRUD — e.g. detect, suggest, generate): prefer reframing as resource creation (`POST /stories` instead of `POST /story/generate/{id}`). When it genuinely isn't a resource, use an **id-first action segment**: `POST /filter/{fileId}/generate`, not `POST /filter/generate/{fileId}`.
- **Pagination**: return `PagedResponse<T>` (`data`, `page`, `pageSize`, `total`, `totalPages`), **1-indexed** `page` + `pageSize` query params. Do not serialize Spring's `Page` directly.
- **Errors**: never hand-build error bodies — throw, and let `GlobalExceptionHandler` map to the shared `ErrorResponse` envelope. `@Valid`/`@Validated` failures return **400** with a `validationErrors` map.
- **DTOs only**: controllers return DTOs, never JPA entities.
- **OpenAPI**: every controller has a `@Tag`, every method an `@Operation`. Swagger UI at `/swagger-ui/index.html` (disabled in prod).

## Offline Requirement

This app must function fully offline (no external API calls at runtime). Keep this in mind for any new features:

- **GeoIP**: Uses a hybrid strategy — `ipinfo.io` when internet is reachable, **DB-IP Lite MMDB** (bundled in the Docker image) as automatic offline fallback. Implemented in `GeoIpService.java` via `com.maxmind.geoip2`. Do not add any other external geo APIs.
- **Maps**: Use static SVG/GeoJSON bundled in the frontend — no tile servers (OpenStreetMap etc.).
- **LLM**: Already configurable via `LLM_BASE_URL` env var pointing to a local inference server (e.g. LM Studio, Ollama).
