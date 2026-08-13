/**
 * Compare mode overlays several captures on one graph to show what changed between them. The
 * ordering matters: each file is built without a node cap, the graphs are merged, and only then
 * is significance applied — capping per file first would drop a host that is minor in one
 * capture but dominant in another, which is exactly the thing a comparison is for.
 */
import { renderHook, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { conversationService } from '@/features/conversation/services/conversationService'
import { networkService } from '../../services/networkService'
import type { GraphNode } from '../../types'
import { useCompareData } from '../useCompareData'

vi.mock('@/features/conversation/services/conversationService', () => ({
  conversationService: { getConversations: vi.fn(), getHostClassifications: vi.fn() },
}))
vi.mock('../../services/networkService', async importOriginal => {
  const actual = await importOriginal<typeof import('../../services/networkService')>()
  return { ...actual, networkService: { buildNetworkGraph: vi.fn() } }
})

const convService = vi.mocked(conversationService)
const netService = vi.mocked(networkService)

function node(id: string, totalBytes = 100): GraphNode {
  return {
    id,
    label: id,
    data: {
      ip: id,
      packetsSent: 1,
      packetsReceived: 1,
      bytesSent: totalBytes,
      bytesReceived: 0,
      totalBytes,
      connections: 1,
      role: 'unknown',
    },
  } as GraphNode
}

function graph(nodes: GraphNode[]) {
  return {
    nodes,
    edges: [],
    stats: { totalNodes: nodes.length, totalEdges: 0, totalPackets: 1, totalBytes: 1 },
  }
}

afterEach(() => vi.resetAllMocks())

describe('useCompareData', () => {
  it('does not fetch until labels have resolved', async () => {
    const { result } = renderHook(() => useCompareData(['f1'], [], 50))

    // Empty labels mean the filenames have not loaded yet. Fetching now would build a graph
    // whose per-file series cannot be named.
    await waitFor(() => expect(convService.getConversations).not.toHaveBeenCalled())
    expect(result.current.loading).toBe(true)
  })

  it('builds every file without a per-file node cap', async () => {
    convService.getConversations.mockResolvedValue({ data: [] } as never)
    convService.getHostClassifications.mockResolvedValue([] as never)
    netService.buildNetworkGraph.mockReturnValue(graph([node('a')]) as never)

    renderHook(() => useCompareData(['f1', 'f2'], ['A', 'B'], 50))

    await waitFor(() => expect(netService.buildNetworkGraph).toHaveBeenCalledTimes(2))
    // The 5th argument is maxNodes; 0 means unlimited. Capping per file would drop a host that
    // is minor in one capture and dominant in another — the comparison's whole subject.
    expect(netService.buildNetworkGraph).toHaveBeenCalledWith(
      expect.anything(), undefined, 500, expect.anything(), 0
    )
  })

  it('reports per-file stats against their labels, in order', async () => {
    convService.getConversations.mockResolvedValue({ data: [] } as never)
    convService.getHostClassifications.mockResolvedValue([] as never)
    netService.buildNetworkGraph
      .mockReturnValueOnce(graph([node('a'), node('b')]) as never)
      .mockReturnValueOnce(graph([node('c')]) as never)

    const { result } = renderHook(() => useCompareData(['f1', 'f2'], ['Monday', 'Tuesday'], 50))

    await waitFor(() => expect(result.current.perFileStats).toHaveLength(2))
    // Misaligning labels and stats would attribute one capture's totals to the other, which is
    // the single most misleading thing this screen could do.
    expect(result.current.perFileStats[0]).toMatchObject({
      label: 'Monday',
      stats: expect.objectContaining({ totalNodes: 2 }),
    })
    expect(result.current.perFileStats[1]).toMatchObject({ label: 'Tuesday' })
  })

  it('applies the node limit after merging and reports what was hidden', async () => {
    convService.getConversations.mockResolvedValue({ data: [] } as never)
    convService.getHostClassifications.mockResolvedValue([] as never)
    netService.buildNetworkGraph.mockReturnValue(
      graph([node('big', 1000), node('mid', 500), node('small', 1)]) as never
    )

    const { result } = renderHook(() => useCompareData(['f1'], ['A'], 2))

    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.mergedNodes).toHaveLength(2)
    expect(result.current.hiddenNodes).toBe(1)
    // totalNodes reports the merged graph, not the visible slice, so the UI can say "showing 2
    // of 3" rather than silently presenting a subset as the whole.
    expect(result.current.totalNodes).toBe(3)
  })

  it('surfaces a fetch failure', async () => {
    convService.getConversations.mockRejectedValue(new Error('backend down'))
    convService.getHostClassifications.mockResolvedValue([] as never)

    const { result } = renderHook(() => useCompareData(['f1'], ['A'], 50))

    await waitFor(() => expect(result.current.error).toBe('backend down'))
    expect(result.current.loading).toBe(false)
  })

  it('recomputes the visible slice when the limit changes without refetching', async () => {
    convService.getConversations.mockResolvedValue({ data: [] } as never)
    convService.getHostClassifications.mockResolvedValue([] as never)
    netService.buildNetworkGraph.mockReturnValue(
      graph([node('big', 1000), node('mid', 500), node('small', 1)]) as never
    )

    const { result, rerender } = renderHook(({ limit }) => useCompareData(['f1'], ['A'], limit), {
      initialProps: { limit: 1 },
    })
    await waitFor(() => expect(result.current.mergedNodes).toHaveLength(1))
    const fetches = convService.getConversations.mock.calls.length

    rerender({ limit: 3 })

    // Memoised on the merged graph, so moving the slider re-slices rather than re-downloading
    // every capture.
    await waitFor(() => expect(result.current.mergedNodes).toHaveLength(3))
    expect(convService.getConversations.mock.calls.length).toBe(fetches)
  })
})
