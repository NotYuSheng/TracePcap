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

/**
 * True only when A and B are the same type.
 *
 * The naive `[A] extends [B] ? ([B] extends [A] ? true : never) : never` is unusable here:
 * its failure value is `never`, and `never` satisfies a `T extends true` constraint, so a
 * mismatched assertion compiles silently and proves nothing. This resolves to `false` on
 * mismatch, which genuinely violates the constraint below.
 */
type Equals<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false

/** Fails to compile unless T is exactly `true`. */
function assertTrue<T extends true>(): void {
  void 0 as unknown as T
}

/**
 * springdoc emits no `required` list for these DTOs, so every generated field is optional
 * and carries `| undefined`. Comparing raw field types would therefore fail everywhere for
 * a reason that says nothing about drift. Strip that one difference and compare the rest,
 * so a genuine change (`number` becoming `string`) still fails.
 */
type Defined<T> = NonNullable<T>

// ---------------------------------------------------------------------------
// The paged envelope. Every list endpoint returns this shape (CLAUDE.md API
// conventions), so a change to it breaks every table in the app at once.
// ---------------------------------------------------------------------------

type BackendPaged = Schema<'PagedResponseFileMetadataDto'>
type FrontendPaged = PaginatedResponse<Defined<BackendPaged['data']>[number]>

// Field sets must match exactly: a field added or renamed on either side fails here.
assertTrue<Equals<keyof FrontendPaged, keyof BackendPaged>>()

// And each field's type must match, ignoring springdoc's blanket optionality.
assertTrue<Equals<FrontendPaged['page'], Defined<BackendPaged['page']>>>()
assertTrue<Equals<FrontendPaged['pageSize'], Defined<BackendPaged['pageSize']>>>()
assertTrue<Equals<FrontendPaged['total'], Defined<BackendPaged['total']>>>()
assertTrue<Equals<FrontendPaged['totalPages'], Defined<BackendPaged['totalPages']>>>()
assertTrue<Equals<FrontendPaged['data'], Defined<BackendPaged['data']>>>()

// ---------------------------------------------------------------------------
// Route typing. A path or method the backend does not serve resolves to `never`,
// so these fail if the route is renamed or its verb changes — the #630 class,
// caught at compile time rather than as a runtime 404.
// ---------------------------------------------------------------------------

assertTrue<Equals<ResponseOf<'/api/v1/files', 'get'>, Schema<'PagedResponseFileMetadataDto'>>>()

// A route that exists is assignable to ApiPath.
const knownRoute: ApiPath = '/api/v1/files'
void knownRoute

// @ts-expect-error - '/api/files' omits the /api/v1 version segment: exactly the #630 bug.
const missingVersionSegment: ApiPath = '/api/files'
void missingVersionSegment
