# TracePcap — Claude Guidelines

## UI Components

**Always use SGDS components first.** Before building a custom UI component, check if `@govtechsg/sgds-react` already provides it. The package is installed and its global CSS is imported via `src/assets/styles/index.css`.

Current SGDS usage: `Container`, `Row`, `Col`, `Card`, `Modal`, `Pagination`.

Only build a custom component if SGDS has no equivalent.

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
