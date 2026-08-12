/**
 * Typed view of the backend contract, derived from `openapi/baseline.json`.
 *
 * `generated/schema.d.ts` is produced by `npm run api:types` and committed. CI regenerates it
 * and fails on any difference, so it cannot drift from the baseline — and the baseline is
 * itself checked against the running backend by `api-schema-drift.yml`.
 *
 * Why this exists: `endpointPaths.test.ts` proves every frontend URL resolves to a real route,
 * but nothing checks the *shapes* crossing that boundary. Hand-written interfaces in
 * `src/types/` mirror backend DTOs by convention only, so a renamed backend field leaves the
 * frontend reading `undefined` with a green build — the same silent-failure class as #630,
 * one layer up. Types sourced from here make that a compile error instead.
 *
 * Prefer `Schema<'SomeDto'>` over adding a hand-written interface for a payload the backend
 * already defines.
 */
import type { components, paths } from './generated/schema'

/** Every DTO the backend publishes, keyed by its OpenAPI schema name. */
export type Schemas = components['schemas']

/** A single backend DTO: `Schema<'ConversationResponse'>`. */
export type Schema<K extends keyof Schemas> = Schemas[K]

/** Every route the backend serves, version prefix included (`/api/v1/files`). */
export type ApiPath = keyof paths

/**
 * The 200 response body for a path + method:
 * `ResponseOf<'/api/v1/files/{fileId}', 'get'>`.
 *
 * Written structurally rather than with `paths[P][M]['responses'][200]...` indexing so it
 * degrades to `never` on a bad path/method pair instead of failing to compile inside this
 * file — the error then lands at the call site, where it is actionable.
 */
export type ResponseOf<
  P extends ApiPath,
  M extends keyof paths[P],
> = paths[P][M] extends {
  responses: { 200: { content: { 'application/json': infer R } } }
}
  ? R
  : never
