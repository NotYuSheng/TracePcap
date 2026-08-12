/**
 * The network graph's data hook. It fans out to four endpoints, but only one of them is
 * required: captures analysed before the classification, identity and role endpoints existed
 * simply have none, and the graph must still draw.
 */
import { renderHook, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { conversationService } from '@/features/conversation/services/conversationService'
import { insightsService } from '@/features/insights/services/insightsService'
import { useNetworkData } from '../useNetworkData'

vi.mock('@/features/conversation/services/conversationService', () => ({
  conversationService: {
    getConversations: vi.fn(),
    getHostClassifications: vi.fn(),
    getHostIdentities: vi.fn(),
  },
}))
vi.mock('@/features/insights/services/insightsService', () => ({
  insightsService: { listNodeRoles: vi.fn() },
}))

const convService = vi.mocked(conversationService)
const insights = vi.mocked(insightsService)

const FILE = '11111111-1111-1111-1111-111111111111'

const conversation = (src: string, dst: string) => ({
  id: `${src}->${dst}`,
  endpoints: [
    { ip: src, port: 1 },
    { ip: dst, port: 2 },
  ],
  protocol: { name: 'TCP', layer: 'transport' },
  packetCount: 1,
  totalBytes: 100,
  startTime: 0,
  endTime: 1,
  flowRisks: [],
  customSignatures: [],
  suricataAlerts: [],
})

/** All four endpoints succeed unless a test overrides one. */
function serveAll() {
  convService.getConversations.mockResolvedValue({
    data: [conversation('10.0.0.1', '8.8.8.8')],
  } as never)
  convService.getHostClassifications.mockResolvedValue([] as never)
  convService.getHostIdentities.mockResolvedValue([] as never)
  insights.listNodeRoles.mockResolvedValue([] as never)
}

afterEach(() => vi.resetAllMocks())

describe('useNetworkData', () => {
  it('builds a graph from the conversations', async () => {
    serveAll()

    const { result } = renderHook(() => useNetworkData(FILE, undefined, 50))

    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.nodes.map(n => n.id).sort()).toEqual(['10.0.0.1', '8.8.8.8'])
    expect(result.current.error).toBeNull()
  })

  it.each([
    ['host classifications', 'getHostClassifications'],
    ['host identities', 'getHostIdentities'],
  ] as const)('still renders when %s are unavailable', async (_label, method) => {
    serveAll()
    convService[method].mockRejectedValue(new Error('404'))

    const { result } = renderHook(() => useNetworkData(FILE, undefined, 50))

    // Best-effort enrichment. Captures analysed before these endpoints existed have none, and
    // an all-or-nothing fetch would blank the graph for every historical file.
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.nodes).toHaveLength(2)
    expect(result.current.error).toBeNull()
  })

  it('still renders when node roles are unavailable', async () => {
    serveAll()
    insights.listNodeRoles.mockRejectedValue(new Error('404'))

    const { result } = renderHook(() => useNetworkData(FILE, undefined, 50))

    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.nodes).toHaveLength(2)
    expect(result.current.error).toBeNull()
  })

  it('fails when conversations cannot be loaded', async () => {
    serveAll()
    convService.getConversations.mockRejectedValue(new Error('backend down'))

    const { result } = renderHook(() => useNetworkData(FILE, undefined, 50))

    // Conversations are the graph. Without them there is nothing to draw, so this is the one
    // rejection that must surface rather than degrade.
    await waitFor(() => expect(result.current.error).toBe('backend down'))
    expect(result.current.nodes).toEqual([])
  })

  it('re-slices without refetching when the node limit changes', async () => {
    serveAll()

    const { result, rerender } = renderHook(
      ({ max }) => useNetworkData(FILE, undefined, max),
      { initialProps: { max: 50 } }
    )
    await waitFor(() => expect(result.current.loading).toBe(false))
    const fetches = convService.getConversations.mock.calls.length

    rerender({ max: 1 })

    // Conversations are cached in a ref precisely so the node-limit slider is instant. Moving
    // it re-downloading a 10,000-conversation page would make the control unusable.
    await waitFor(() => expect(result.current.nodes).toHaveLength(1))
    expect(convService.getConversations.mock.calls.length).toBe(fetches)
    expect(result.current.hiddenNodes).toBe(1)
  })

  it('refetches on demand', async () => {
    serveAll()

    const { result } = renderHook(() => useNetworkData(FILE, undefined, 50))
    await waitFor(() => expect(result.current.loading).toBe(false))
    const before = convService.getConversations.mock.calls.length

    await result.current.refetch()

    expect(convService.getConversations.mock.calls.length).toBe(before + 1)
  })
})
