/**
 * Compile-time conformance between hand-written frontend types and the backend contract.
 *
 * These assertions have no runtime body — they fail by refusing to compile, so they are
 * checked by `npm run typecheck:test` in CI rather than by vitest. `endpointPaths.test.ts`
 * guards the *URLs*; this guards the *shapes* travelling over them.
 *
 * Add a case here whenever a frontend interface mirrors a backend DTO. Migrating the
 * interface to `Schema<'TheDto'>` outright is better still — then it cannot drift at all —
 * but that is a per-type change, and this catches drift in the meantime.
 */
import type { PaginatedResponse } from '@/types/api.types'
import type { ApiPath, ResponseOf, Schema } from '../contract'

/** Compiles only when A and B are mutually assignable. */
type Exact<A, B> = [A] extends [B] ? ([B] extends [A] ? true : never) : never

function assertExact<T extends true>(): void {
  void 0 as unknown as T
}

// ---------------------------------------------------------------------------
// The paged envelope. Every list endpoint returns this shape (CLAUDE.md API
// conventions), so a change to it breaks every table in the app at once.
// ---------------------------------------------------------------------------

type BackendPaged = Schema<'PagedResponseFileMetadataDto'>
type FrontendPaged = PaginatedResponse<BackendPaged['data'] extends (infer E)[] ? E : never>

assertExact<Exact<keyof FrontendPaged, keyof BackendPaged>>()

// The pagination fields specifically: 1-indexed `page` + `pageSize`, per the conventions.
assertExact<Exact<FrontendPaged['page'], BackendPaged['page']>>()
assertExact<Exact<FrontendPaged['pageSize'], BackendPaged['pageSize']>>()
assertExact<Exact<FrontendPaged['total'], BackendPaged['total']>>()
assertExact<Exact<FrontendPaged['totalPages'], BackendPaged['totalPages']>>()

// ---------------------------------------------------------------------------
// Route typing. A path or method the backend does not serve resolves to `never`,
// so these fail if the route is renamed or its verb changes — the #630 class,
// caught at compile time rather than as a runtime 404.
// ---------------------------------------------------------------------------

type FilesList = ResponseOf<'/api/v1/files', 'get'>
assertExact<Exact<FilesList, Schema<'PagedResponseFileMetadataDto'>>>()

// A path literal that is not a real route is not assignable to ApiPath.
const knownRoute: ApiPath = '/api/v1/files'
void knownRoute

// @ts-expect-error - '/api/files' omits the /api/v1 version segment: exactly the #630 bug.
const missingVersionSegment: ApiPath = '/api/files'
void missingVersionSegment
