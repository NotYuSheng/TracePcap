/**
 * When a capture has more hosts than the graph will draw, this function decides which ones an
 * analyst sees. Getting it wrong hides hosts that matter, and the hiding is silent — the graph
 * looks complete either way.
 *
 * Score = 0.5 * (bytes / maxBytes) + 0.3 * (has risk) + 0.2 * (connections / maxConnections).
 */
import { describe, expect, it } from 'vitest'

import type { GraphEdge, GraphNode } from '@/features/network/types'
import { selectSignificantNodes } from '../networkService'

function node(id: string, totalBytes: number, connections = 1): GraphNode {
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
      connections,
      role: 'unknown',
    } as GraphNode['data'],
  }
}

function edge(source: string, target: string, risky = false): GraphEdge {
  return {
    id: `${source}->${target}`,
    source,
    target,
    label: 'TCP',
    data: {
      protocol: 'TCP',
      packetCount: 1,
      totalBytes: 1,
      conversationId: `${source}->${target}`,
      bidirectional: false,
      hasRisks: risky,
    } as GraphEdge['data'],
  }
}

const ids = (nodes: GraphNode[]) => nodes.map(n => n.id)

describe('selectSignificantNodes', () => {
  it('hides nothing when the graph fits inside the limit', () => {
    const nodes = [node('a', 10), node('b', 20)]

    const result = selectSignificantNodes(nodes, [], 5)

    expect(result.hiddenCount).toBe(0)
    expect(result.hiddenNodesList).toEqual([])
    expect(result.crossEdges).toEqual([])
  })

  it('keeps the highest-traffic host when traffic is the only signal', () => {
    const nodes = [node('quiet', 1), node('loud', 1000)]

    const result = selectSignificantNodes(nodes, [], 1)

    expect(ids(result.significantNodes)).toEqual(['loud'])
    expect(result.hiddenCount).toBe(1)
  })

  it('promotes a risky host over an equally busy clean one', () => {
    const nodes = [node('clean', 100), node('risky', 100)]
    const edges = [edge('risky', 'peer', true)]

    const result = selectSignificantNodes(nodes, edges, 1)

    // Risk is worth 0.3, so it breaks the tie — which is the point of scoring rather than
    // sorting on bytes alone.
    expect(ids(result.significantNodes)).toEqual(['risky'])
  })

  it('marks both endpoints of a risky edge, not just the source', () => {
    // Scores, with maxBytes = 2 and every node on 1 connection:
    //   src  0.5*(1/2) + 0.3 + 0.2 = 0.75
    //   dst  0.5*(1/2) + 0.3 + 0.2 = 0.75
    //   bulk 0.5*(2/2) + 0.0 + 0.2 = 0.70
    // so the risky pair edges out the busier host by a margin the risk flag supplies.
    const nodes = [node('src', 1), node('dst', 1), node('bulk', 2)]
    const edges = [edge('src', 'dst', true)]

    const result = selectSignificantNodes(nodes, edges, 2)

    // A risk belongs to the conversation, so the peer is as interesting as the initiator.
    expect(ids(result.significantNodes).sort()).toEqual(['dst', 'src'])
  })

  it('reports cross-edges only where exactly one endpoint was hidden', () => {
    const nodes = [node('keep1', 100), node('keep2', 90), node('drop', 1)]
    const edges = [edge('keep1', 'keep2'), edge('keep1', 'drop'), edge('drop', 'drop')]

    const result = selectSignificantNodes(nodes, edges, 2)

    // These drive the "N hidden hosts" affordance. A visible↔visible edge is already drawn,
    // and a hidden↔hidden edge is invisible either way.
    expect(result.crossEdges.map(e => e.id)).toEqual(['keep1->drop'])
  })

  it('counts hidden nodes consistently with the returned list', () => {
    const nodes = [node('a', 5), node('b', 4), node('c', 3), node('d', 2)]

    const result = selectSignificantNodes(nodes, [], 2)

    expect(result.hiddenCount).toBe(result.hiddenNodesList.length)
    expect(result.hiddenCount).toBe(2)
  })

  describe('known looseness — pinned, not endorsed', () => {
    it('still hides a risky host when its traffic is small enough', () => {
      // Risk contributes at most 0.3 while traffic contributes up to 0.5, so a flagged host
      // with little traffic loses to busy clean ones. An analyst who assumes "risky hosts are
      // always shown" would be wrong, and nothing in the UI says otherwise.
      const nodes = [node('loud1', 1000), node('loud2', 999), node('risky', 1)]
      const edges = [edge('risky', 'peer', true)]

      const result = selectSignificantNodes(nodes, edges, 2)

      expect(ids(result.significantNodes)).toEqual(['loud1', 'loud2'])
      expect(ids(result.hiddenNodesList)).toContain('risky')
    })
  })
})
