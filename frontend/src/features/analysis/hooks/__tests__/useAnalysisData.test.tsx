/**
 * Analysis runs asynchronously on the backend, so this hook polls until it finishes. Three HTTP
 * statuses mean three different things — done, still working, failed — and treating any of them
 * as another either spins forever or reports success on a failed run.
 */
import { renderHook, waitFor } from '@testing-library/react'
import { HttpResponse, http } from 'msw'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { server } from '@/test/msw'
import { useStore } from '@/store'
import { useAnalysisData } from '../useAnalysisData'

const FILE = '11111111-1111-1111-1111-111111111111'
const summary = { fileId: FILE, fileName: 'a.pcap', totalPackets: 10 }

/** Serves /system/limits plus a scripted sequence of summary responses. */
function serveSequence(statuses: number[]) {
  let call = 0
  const seen = { calls: 0 }
  server.use(
    http.get('*/system/limits', () => HttpResponse.json({ analysisTimeoutMs: 300000 })),
    http.get('*/analysis/*/summary', () => {
      seen.calls += 1
      const status = statuses[Math.min(call++, statuses.length - 1)]
      if (status === 200) return HttpResponse.json(summary)
      return HttpResponse.json({ message: 'x' }, { status })
    })
  )
  return seen
}

beforeEach(() => {
  useStore.setState({ analysisSummaries: {} } as never)
})
afterEach(() => vi.useRealTimers())

describe('useAnalysisData', () => {
  it('resolves immediately on a 200', async () => {
    serveSequence([200])

    const { result } = renderHook(() => useAnalysisData(FILE))

    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.data).toMatchObject({ fileId: FILE })
    expect(result.current.error).toBeNull()
  })

  it('keeps polling on a 202 and settles once analysis completes', async () => {
    const seen = serveSequence([202, 202, 200])
    vi.useFakeTimers({ shouldAdvanceTime: true })

    const { result } = renderHook(() => useAnalysisData(FILE))
    await waitFor(() => expect(seen.calls).toBeGreaterThanOrEqual(1))

    // 202 means "still working" — treating it as an error would abandon every large capture
    // partway through.
    expect(result.current.loading).toBe(true)

    await vi.advanceTimersByTimeAsync(2000)
    await vi.advanceTimersByTimeAsync(2000)

    await waitFor(() => expect(result.current.data).toMatchObject({ fileId: FILE }))
    expect(result.current.loading).toBe(false)
  })

  it('reports a server-side failure rather than polling forever', async () => {
    serveSequence([500])

    const { result } = renderHook(() => useAnalysisData(FILE))

    await waitFor(() => expect(result.current.error).not.toBeNull())
    expect(result.current.error?.message).toBe('Analysis failed on server')
    expect(result.current.loading).toBe(false)
  })

  it('stops polling after a failure — but only from the second poll onward', async () => {
    const seen = serveSequence([500])
    vi.useFakeTimers({ shouldAdvanceTime: true })

    const { result } = renderHook(() => useAnalysisData(FILE))
    await waitFor(() => expect(result.current.error).not.toBeNull())

    await vi.advanceTimersByTimeAsync(6000)

    // Pinned, not endorsed. The interval is created *after* the first poll is awaited:
    //
    //   await pollStatus();                         // 500 → clearInterval(pollInterval)
    //   pollInterval = setInterval(pollStatus, ...) // …but it was still null above
    //
    // so the terminal status on the first poll clears nothing and the interval starts anyway.
    // The second poll hits the same status and clears it properly, which caps the leak at one
    // extra request rather than letting it run forever. The same ordering applies to a 200, so
    // every completed analysis costs one redundant fetch.
    //
    // Cheap to fix by hoisting the setInterval above the await, but that changes request
    // timing on a path this suite is meant to hold still first.
    expect(seen.calls).toBe(2)
  })

  it('stops polling on unmount', async () => {
    const seen = serveSequence([202])
    vi.useFakeTimers({ shouldAdvanceTime: true })

    const { unmount } = renderHook(() => useAnalysisData(FILE))
    await waitFor(() => expect(seen.calls).toBeGreaterThanOrEqual(1))

    unmount()
    const afterUnmount = seen.calls
    await vi.advanceTimersByTimeAsync(6000)

    // Navigating away from a still-processing capture must not leave a 2s interval running for
    // the life of the session.
    expect(seen.calls).toBe(afterUnmount)
  })

  it('serves a cached summary without hitting the network', async () => {
    const seen = serveSequence([200])
    useStore.setState({ analysisSummaries: { [FILE]: summary } } as never)

    const { result } = renderHook(() => useAnalysisData(FILE))

    // Revisiting an analysed capture is the common case; re-polling it would add latency to
    // every navigation for a result that cannot change.
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.data).toMatchObject({ fileId: FILE })
    expect(seen.calls).toBe(0)
  })
})
