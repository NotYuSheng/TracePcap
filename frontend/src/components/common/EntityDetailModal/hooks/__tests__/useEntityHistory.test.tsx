/**
 * Which uploaded captures an entity appeared in. Small hook, but it is the one that answers
 * "have we seen this host before" — so an empty list must mean "never seen", not "the request
 * failed".
 */
import { renderHook, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  entityNotesService,
  type EntityHistoryEntry,
} from '@/features/notes/services/entityNotesService'
import { useEntityHistory } from '../useEntityHistory'

vi.mock('@/features/notes/services/entityNotesService', () => ({
  entityNotesService: { getHistory: vi.fn() },
}))

const mocked = vi.mocked(entityNotesService)

const entry = (fileId: string): EntityHistoryEntry => ({
  fileId,
  fileName: `${fileId}.pcap`,
  startTime: null,
  endTime: null,
  packetCount: null,
  totalBytes: null,
})

afterEach(() => vi.resetAllMocks())

describe('useEntityHistory', () => {
  it('loads the capture history', async () => {
    mocked.getHistory.mockResolvedValue([entry('f1'), entry('f2')])

    const { result } = renderHook(() => useEntityHistory('IP', '10.0.0.1'))

    await waitFor(() => expect(result.current.history).toHaveLength(2))
    expect(result.current.historyError).toBeNull()
    expect(result.current.historyLoading).toBe(false)
  })

  it('distinguishes a failure from an empty history', async () => {
    mocked.getHistory.mockRejectedValue(new Error('backend down'))

    const { result } = renderHook(() => useEntityHistory('IP', '10.0.0.1'))

    // Both leave `history` empty, so the error flag is the only thing separating "this host is
    // new" from "we could not check". Reporting the first when the second is true would let an
    // analyst treat a known host as unseen.
    await waitFor(() => expect(result.current.historyError).toBe('Failed to load history'))
    expect(result.current.history).toEqual([])
    expect(result.current.historyLoading).toBe(false)
  })

  it('clears the previous entity history immediately on switch', async () => {
    mocked.getHistory.mockResolvedValue([entry('f1')])
    const { result, rerender } = renderHook(({ key }) => useEntityHistory('IP', key), {
      initialProps: { key: '10.0.0.1' },
    })
    await waitFor(() => expect(result.current.history).toHaveLength(1))

    mocked.getHistory.mockReturnValue(new Promise(() => {}))
    rerender({ key: '10.0.0.2' })

    // The modal is reused, so one host's capture history must not sit under another's heading.
    expect(result.current.history).toEqual([])
  })

  it('clears a stale error when a new entity loads cleanly', async () => {
    mocked.getHistory.mockRejectedValueOnce(new Error('boom'))
    const { result, rerender } = renderHook(({ key }) => useEntityHistory('IP', key), {
      initialProps: { key: '10.0.0.1' },
    })
    await waitFor(() => expect(result.current.historyError).not.toBeNull())

    mocked.getHistory.mockResolvedValue([entry('f1')])
    rerender({ key: '10.0.0.2' })

    // A left-over error would label a perfectly good history as broken.
    //
    // Both fields are asserted inside one waitFor rather than sequentially: the first
    // entity's rejection can still be settling when the rerender happens, so the error is
    // briefly non-null again. Checking them one at a time made this flake roughly one run in
    // five — a flaky test is worse than none, because it teaches people to re-run.
    await waitFor(() => {
      expect(result.current.historyError).toBeNull()
      expect(result.current.history).toHaveLength(1)
    })
  })

  it('ignores a slow response for an entity the user has already left', async () => {
    let resolveFirst: (v: EntityHistoryEntry[]) => void = () => {}
    mocked.getHistory.mockImplementationOnce(
      () => new Promise<EntityHistoryEntry[]>(res => { resolveFirst = res })
    )

    const { result, rerender } = renderHook(({ key }) => useEntityHistory('IP', key), {
      initialProps: { key: '10.0.0.1' },
    })

    mocked.getHistory.mockResolvedValue([entry('second')])
    rerender({ key: '10.0.0.2' })
    await waitFor(() => expect(result.current.history[0]?.fileId).toBe('second'))

    await waitFor(async () => { resolveFirst([entry('first')]) })

    expect(result.current.history[0]?.fileId).toBe('second')
  })
})
