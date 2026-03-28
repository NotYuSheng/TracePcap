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
