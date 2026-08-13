/**
 * Aggregate stats for an application or protocol, computed server-side so the numbers stay
 * internally consistent however many conversations match (#436). The hook's job is deciding
 * *when* to ask and *how* to name the filter — get either wrong and the modal shows another
 * entity's totals, or none.
 */
import { renderHook, waitFor } from '@testing-library/react'
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '@/test/msw'
import { useEntityStats } from '../useEntityStats'

const FILE = '11111111-1111-1111-1111-111111111111'

const payload = {
  conversationCount: 3,
  packetCount: 300,
  totalBytes: 30000,
  topPeers: [{ ip: '8.8.8.8', bytes: 1000 }],
}

/** Serves the stats endpoint and records the query it was asked with. */
function serveStats(status = 200) {
  const seen: { query?: URLSearchParams; calls: number } = { calls: 0 }
  server.use(
    http.get('*/entity-stats', ({ request }) => {
      seen.calls += 1
      seen.query = new URL(request.url).searchParams
      return status === 200
        ? HttpResponse.json(payload)
        : HttpResponse.json({ message: 'boom' }, { status })
    })
  )
  return seen
}

describe('useEntityStats', () => {
  it('loads stats for an APPLICATION entity', async () => {
    serveStats()

    const { result } = renderHook(() => useEntityStats('APPLICATION', 'TLS', FILE))

    await waitFor(() => expect(result.current.stats).not.toBeNull())
    expect(result.current.stats).toEqual(payload)
    expect(result.current.statsError).toBeNull()
  })

  it('filters by app for an APPLICATION and by l7Protocol for a PROTOCOL', async () => {
    const app = serveStats()
    const { unmount } = renderHook(() => useEntityStats('APPLICATION', 'TLS', FILE))
    await waitFor(() => expect(app.query?.get('app')).toBe('TLS'))
    unmount()

    const proto = serveStats()
    renderHook(() => useEntityStats('PROTOCOL', 'TCP', FILE))

    // Two different backend filters behind one modal. Swapping them returns stats for a
    // different entity entirely, with nothing to indicate the mix-up.
    await waitFor(() => expect(proto.query?.get('l7Protocol')).toBe('TCP'))
    expect(proto.query?.has('app')).toBe(false)
  })

  it('encodes an entity key containing URL-significant characters', async () => {
    const seen = serveStats()

    renderHook(() => useEntityStats('APPLICATION', 'Google/Maps', FILE))

    // A raw "/" would change the path; "&" would start a second parameter.
    await waitFor(() => expect(seen.query?.get('app')).toBe('Google/Maps'))
  })

  it.each(['IP', 'DEVICE'] as const)('does not fetch for a %s entity', async entityType => {
    const seen = serveStats()

    const { result } = renderHook(() => useEntityStats(entityType, '10.0.0.1', FILE))

    // The endpoint only aggregates applications and protocols; asking it about a host would
    // return nothing useful and cost a request per modal open.
    await waitFor(() => expect(result.current.statsLoading).toBe(false))
    expect(seen.calls).toBe(0)
    expect(result.current.stats).toBeNull()
  })

  it.each([
    ['a missing fileId', ''],
    ['a blank entity key', '   '],
  ])('does not fetch with %s', async (_label, key) => {
    const seen = serveStats()
    const fileId = key === '' ? '' : FILE
    const entityKey = key === '' ? 'TLS' : key

    renderHook(() => useEntityStats('APPLICATION', entityKey, fileId))

    await waitFor(() => expect(seen.calls).toBe(0))
  })

  it('surfaces a failure as an error message rather than silence', async () => {
    serveStats(500)

    const { result } = renderHook(() => useEntityStats('APPLICATION', 'TLS', FILE))

    // Contrast with useEntityNote, which swallows failures to console.error. Here the modal
    // can tell the analyst the totals are unavailable instead of implying they are zero.
    await waitFor(() => expect(result.current.statsError).toBe('Failed to load details'))
    expect(result.current.stats).toBeNull()
    expect(result.current.statsLoading).toBe(false)
  })

  it('clears previous stats when the entity changes', async () => {
    serveStats()
    const { result, rerender } = renderHook(({ key }) => useEntityStats('APPLICATION', key, FILE), {
      initialProps: { key: 'TLS' },
    })
    await waitFor(() => expect(result.current.stats).not.toBeNull())

    server.use(http.get('*/entity-stats', () => new Promise(() => {}) as never))
    rerender({ key: 'HTTP' })

    // The modal is reused across entities, so stale totals must not sit under a new heading
    // while the next request is in flight.
    expect(result.current.stats).toBeNull()
  })
})
