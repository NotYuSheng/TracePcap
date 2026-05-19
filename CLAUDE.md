# Lanturn — Claude Guidelines

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

## Offline Requirement

This app must function fully offline (no external API calls at runtime). Keep this in mind for any new features:

- **GeoIP**: Uses a hybrid strategy — `ipinfo.io` when internet is reachable, **DB-IP Lite MMDB** (bundled in the Docker image) as automatic offline fallback. Implemented in `GeoIpService.java` via `com.maxmind.geoip2`. Do not add any other external geo APIs.
- **Maps**: Use static SVG/GeoJSON bundled in the frontend — no tile servers (OpenStreetMap etc.).
- **LLM**: Already configurable via `LLM_BASE_URL` env var pointing to a local inference server (e.g. LM Studio, Ollama).
