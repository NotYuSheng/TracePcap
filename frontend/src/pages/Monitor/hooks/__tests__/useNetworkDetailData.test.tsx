/**
 * The monitor detail page loads eight endpoints and then polls them. The property that matters
 * most is the one you only notice when it is wrong: a background refresh must not raise the
 * loading flag, or the page blanks itself every thirty seconds while an operator is reading it.
 */
import { renderHook, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { monitorService } from '@/features/monitor/services/monitorService'
import { insightsService } from '@/features/insights/services/insightsService'
import { subnetService } from '@/features/subnets/services/subnetService'
import { useNetworkDetailData } from '../useNetworkDetailData'

vi.mock('@/features/monitor/services/monitorService', () => ({
  monitorService: {
    getNetwork: vi.fn(),
    listSnapshots: vi.fn(),
    listChanges: vi.fn(),
    listDefinitions: vi.fn(),
    addSnapshot: vi.fn(),
    removeSnapshot: vi.fn(),
  },
}))
vi.mock('@/features/insights/services/insightsService', () => ({
  insightsService: {
    listExternalEvents: vi.fn(),
    listAnnotations: vi.fn(),
    getLatestInsight: vi.fn(),
  },
}))
vi.mock('@/features/subnets/services/subnetService', () => ({
  subnetService: { list: vi.fn() },
}))

const monitor = vi.mocked(monitorService)
const insights = vi.mocked(insightsService)
const subnets = vi.mocked(subnetService)

const NET = 'net-1'

function serveAll() {
  monitor.getNetwork.mockResolvedValue({ id: NET, name: 'HQ' } as never)
  monitor.listSnapshots.mockResolvedValue([] as never)
  monitor.listChanges.mockResolvedValue([] as never)
  monitor.listDefinitions.mockResolvedValue([] as never)
  insights.listExternalEvents.mockResolvedValue([] as never)
  insights.listAnnotations.mockResolvedValue([] as never)
  insights.getLatestInsight.mockResolvedValue(null as never)
  subnets.list.mockResolvedValue([] as never)
}

afterEach(() => {
  vi.useRealTimers()
  vi.resetAllMocks()
})

describe('useNetworkDetailData', () => {
  it('loads the network on mount', async () => {
    serveAll()

    const { result } = renderHook(() => useNetworkDetailData(NET))

    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.network).toMatchObject({ id: NET })
    expect(result.current.lastUpdated).toBeInstanceOf(Date)
    expect(result.current.error).toBeNull()
  })

  it('does not raise the loading flag on a background poll', async () => {
    serveAll()
    vi.useFakeTimers({ shouldAdvanceTime: true })

    const { result } = renderHook(() => useNetworkDetailData(NET))
    await waitFor(() => expect(result.current.loading).toBe(false))
    const firstLoad = monitor.getNetwork.mock.calls.length

    // Hold the poll's first request open. Asserting after the poll settles proves nothing —
    // loadAll(true) would set loading and clear it again before the assertion ran, so an
    // earlier version of this test passed even with the spinner reinstated.
    let releasePoll: () => void = () => {}
    monitor.getNetwork.mockImplementationOnce(
      () => new Promise(res => { releasePoll = () => res({ id: NET, name: 'HQ' } as never) })
    )

    await vi.advanceTimersByTimeAsync(30000)
    await waitFor(() => expect(monitor.getNetwork.mock.calls.length).toBeGreaterThan(firstLoad))

    // Mid-poll: if the interval used loadAll(true), the whole page would swap to a spinner
    // every thirty seconds under an operator who is mid-read.
    expect(result.current.loading).toBe(false)

    releasePoll()
  })

  it('stops polling when the interval is set to zero', async () => {
    serveAll()
    vi.useFakeTimers({ shouldAdvanceTime: true })

    const { result } = renderHook(() => useNetworkDetailData(NET))
    await waitFor(() => expect(result.current.loading).toBe(false))

    result.current.setPollInterval(0)
    await waitFor(() => expect(result.current.pollInterval).toBe(0))
    const afterDisable = monitor.getNetwork.mock.calls.length

    await vi.advanceTimersByTimeAsync(120000)

    expect(monitor.getNetwork.mock.calls.length).toBe(afterDisable)

    // Caveat, stated rather than glossed: removing the `pollInterval === 0` guard does make
    // this file fail, but by destabilising the run rather than by failing this assertion —
    // setInterval(fn, 0) busy-loops. Spying on setInterval instead does not work either,
    // because waitFor uses it internally. So the guard is covered, but the diagnosis on
    // regression will be "this file died", not "polling was not disabled".
  })

  it('stops polling on unmount', async () => {
    serveAll()
    vi.useFakeTimers({ shouldAdvanceTime: true })

    const { result, unmount } = renderHook(() => useNetworkDetailData(NET))
    await waitFor(() => expect(result.current.loading).toBe(false))

    unmount()
    const afterUnmount = monitor.getNetwork.mock.calls.length
    await vi.advanceTimersByTimeAsync(90000)

    expect(monitor.getNetwork.mock.calls.length).toBe(afterUnmount)
  })

  it('reports a load failure without leaving the spinner up', async () => {
    serveAll()
    monitor.getNetwork.mockRejectedValue(new Error('backend down'))

    const { result } = renderHook(() => useNetworkDetailData(NET))

    await waitFor(() => expect(result.current.error).toBe('Failed to load network data.'))
    expect(result.current.loading).toBe(false)
  })

  it('refreshes after adding a snapshot', async () => {
    serveAll()
    monitor.addSnapshot.mockResolvedValue({ id: 's1' } as never)

    const { result } = renderHook(() => useNetworkDetailData(NET))
    await waitFor(() => expect(result.current.loading).toBe(false))
    const before = monitor.listSnapshots.mock.calls.length

    await result.current.handleAddSnapshot('file-1')

    // A snapshot changes every panel on the page — change events, insights, definitions — so
    // the reload is a full one rather than a local append.
    expect(monitor.addSnapshot).toHaveBeenCalledWith(NET, 'file-1', undefined)
    expect(monitor.listSnapshots.mock.calls.length).toBeGreaterThan(before)
  })

  it('patches a single snapshot in place without refetching', async () => {
    serveAll()
    monitor.listSnapshots.mockResolvedValue([
      { id: 's1', label: 'old' },
      { id: 's2', label: 'other' },
    ] as never)

    const { result } = renderHook(() => useNetworkDetailData(NET))
    await waitFor(() => expect(result.current.snapshots).toHaveLength(2))
    const before = monitor.listSnapshots.mock.calls.length

    result.current.handleSnapshotUpdated({ id: 's1', label: 'renamed' } as never)

    // Renaming a snapshot is a local edit; a full reload would discard scroll position and
    // re-run eight requests for a label change.
    await waitFor(() =>
      expect(result.current.snapshots.find(s => s.id === 's1')).toMatchObject({ label: 'renamed' })
    )
    expect(result.current.snapshots.find(s => s.id === 's2')).toMatchObject({ label: 'other' })
    expect(monitor.listSnapshots.mock.calls.length).toBe(before)
  })

  it('does nothing without a network id', async () => {
    serveAll()

    const { result } = renderHook(() => useNetworkDetailData(''))

    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(monitor.getNetwork).not.toHaveBeenCalled()
  })
})
