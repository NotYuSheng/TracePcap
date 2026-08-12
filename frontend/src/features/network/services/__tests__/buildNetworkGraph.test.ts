/**
 * buildNetworkGraph turns conversations into the graph an analyst reads. It is the largest
 * function in the frontend and had no tests, so these cover its observable contracts — node and
 * edge construction, the caps that keep a big capture renderable, and the seeding that makes the
 * node count agree with the analysis summary — rather than every internal branch.
 */
import { describe, expect, it } from 'vitest'

import type { Conversation } from '@/types'
import { buildNetworkGraph } from '../networkService'

function conversation(src: string, dst: string, overrides: Partial<Conversation> = {}): Conversation {
  return {
    id: `${src}->${dst}`,
    endpoints: [
      { ip: src, port: 1234 },
      { ip: dst, port: 443 },
    ],
    protocol: { name: 'TCP', layer: 'Transport' },
    packetCount: 10,
    totalBytes: 1000,
    startTime: 0,
    endTime: 1,
    flowRisks: [],
    customSignatures: [],
    suricataAlerts: [],
    ...overrides,
  } as unknown as Conversation
}

describe('buildNetworkGraph', () => {
  it('creates one node per distinct host and one edge per conversation', () => {
    const result = buildNetworkGraph([conversation('10.0.0.1', '8.8.8.8')])

    expect(result.nodes.map(n => n.id).sort()).toEqual(['10.0.0.1', '8.8.8.8'])
    expect(result.edges).toHaveLength(1)
  })

  it('reuses a node when a host appears in several conversations', () => {
    const result = buildNetworkGraph([
      conversation('10.0.0.1', '8.8.8.8'),
      conversation('10.0.0.1', '1.1.1.1'),
    ])

    // Three hosts, not four: the shared host must be one node or the graph double-counts it.
    expect(result.nodes).toHaveLength(3)
    expect(result.edges).toHaveLength(2)
  })

  it('accumulates traffic onto the shared node rather than overwriting it', () => {
    const result = buildNetworkGraph([
      conversation('10.0.0.1', '8.8.8.8', { packetCount: 10, totalBytes: 1000 }),
      conversation('10.0.0.1', '1.1.1.1', { packetCount: 5, totalBytes: 500 }),
    ])

    const shared = result.nodes.find(n => n.id === '10.0.0.1')!
    // Node size and ranking are driven by these totals, so overwriting would shrink a busy host.
    expect(shared.data.bytesSent).toBe(1500)
  })

  it('caps the conversations it will render', () => {
    const many = Array.from({ length: 10 }, (_, i) => conversation('10.0.0.1', `8.8.8.${i}`))

    const result = buildNetworkGraph(many, undefined, 3)

    // The cap exists so a 100k-conversation capture still renders; without it the browser hangs.
    expect(result.edges).toHaveLength(3)
  })

  it('reports statistics consistent with the graph it built', () => {
    const result = buildNetworkGraph([
      conversation('10.0.0.1', '8.8.8.8', { packetCount: 10 }),
      conversation('10.0.0.2', '1.1.1.1', { packetCount: 5 }),
    ])

    expect(result.stats.totalNodes).toBe(result.nodes.length)
    expect(result.stats.totalEdges).toBe(result.edges.length)
  })

  it('breaks packet counts down by protocol', () => {
    const result = buildNetworkGraph([
      conversation('10.0.0.1', '8.8.8.8', {
        protocol: { name: 'TCP', layer: 'Transport' },
        packetCount: 10,
      } as Partial<Conversation>),
      conversation('10.0.0.2', '1.1.1.1', {
        protocol: { name: 'UDP', layer: 'Transport' },
        packetCount: 4,
      } as Partial<Conversation>),
    ])

    expect(result.stats.protocolBreakdown).toMatchObject({ TCP: 10, UDP: 4 })
  })

  it('marks an edge as risky when the conversation carries flow risks', () => {
    const result = buildNetworkGraph([
      conversation('10.0.0.1', '8.8.8.8', {
        flowRisks: ['Self-signed certificate'],
      } as Partial<Conversation>),
    ])

    // selectSignificantNodes reads hasRisks to decide visibility, so this flag is what keeps a
    // flagged host on screen when the graph is capped.
    expect(result.edges[0].data.hasRisks).toBe(true)
  })

  it('returns an empty graph for no conversations rather than throwing', () => {
    const result = buildNetworkGraph([])

    expect(result.nodes).toEqual([])
    expect(result.edges).toEqual([])
    expect(result.stats.totalNodes).toBe(0)
  })
})
