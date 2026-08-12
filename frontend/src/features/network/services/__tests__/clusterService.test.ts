/**
 * Subnet clustering decides what the network graph actually shows. Collapse too eagerly and
 * hosts an analyst is looking for vanish into a cluster; collapse too little and the graph is
 * unreadable. It is pure — no HTTP — so this is the cheapest high-value logic in the frontend
 * and it had no tests.
 */
import { describe, expect, it } from 'vitest'

import type { GraphEdge, GraphNode } from '@/features/network/types'
import { applySubnetClustering } from '../clusterService'

function node(ip: string): GraphNode {
  return {
    id: ip,
    label: ip,
    data: {
      ip,
      packetsSent: 1,
      packetsReceived: 1,
      bytesSent: 1,
      bytesReceived: 1,
      totalBytes: 2,
      role: 'unknown',
    } as GraphNode['data'],
  }
}

function edge(source: string, target: string): GraphEdge {
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
    } as GraphEdge['data'],
  }
}

const ids = (nodes: GraphNode[]) => nodes.map(n => n.id).sort()

describe('applySubnetClustering', () => {
  it('collapses two or more hosts sharing a /24', () => {
    const nodes = [node('10.0.1.5'), node('10.0.1.6'), node('10.0.1.7')]

    const result = applySubnetClustering(nodes, [], new Set())

    // One cluster stands in for all three; the members are no longer drawn individually.
    expect(result.nodes).toHaveLength(1)
    expect(result.nodes[0].id).toContain('10.0.1.0/24')
  })

  it('leaves a lone host in its /24 uncollapsed rather than making a cluster of one', () => {
    const nodes = [node('10.0.1.5'), node('192.168.9.9')]

    const result = applySubnetClustering(nodes, [], new Set())

    // A cluster of one is strictly worse than the node: same information, extra indirection.
    expect(result.nodes).toHaveLength(2)
  })

  it('promotes scattered single-host /24s to a /16 so they still group', () => {
    // The case the two-pass strategy exists for: 250 unique /24s would otherwise stay 250
    // separate nodes and make the graph unreadable.
    const nodes = [node('10.0.1.5'), node('10.0.2.5'), node('10.0.3.5')]

    const result = applySubnetClustering(nodes, [], new Set())

    expect(result.nodes).toHaveLength(1)
    expect(result.nodes[0].id).toContain('10.0.0.0/16')
  })

  it('expands a cluster back into its members on request', () => {
    const nodes = [node('10.0.1.5'), node('10.0.1.6')]
    const collapsed = applySubnetClustering(nodes, [], new Set())
    const clusterId = collapsed.nodes[0].id

    const expanded = applySubnetClustering(nodes, [], new Set([clusterId]))

    expect(ids(expanded.nodes)).toEqual(['10.0.1.5', '10.0.1.6'])
  })

  it('rewires an edge to the cluster that swallowed its endpoint', () => {
    const nodes = [node('10.0.1.5'), node('10.0.1.6'), node('8.8.8.8')]
    const edges = [edge('10.0.1.5', '8.8.8.8')]

    const result = applySubnetClustering(nodes, edges, new Set())

    // The edge must survive: dropping it would hide that the cluster talks to 8.8.8.8 at all.
    expect(result.edges).toHaveLength(1)
    expect(result.edges[0].source).toContain('10.0.1.0/24')
    expect(result.edges[0].target).toBe('8.8.8.8')
  })

  it.each([
    ['127.0.0.1', 'loopback'],
    ['169.254.1.1', 'link-local'],
    ['224.0.0.251', 'multicast'],
    ['239.255.255.250', 'multicast (SSDP)'],
    ['fe80::1', 'IPv6 link-local'],
  ])('never clusters %s (%s)', ip => {
    // These carry meaning individually — mDNS and SSDP traffic is how devices are identified,
    // so folding them into a subnet blob destroys the signal.
    const nodes = [node(ip), node(ip.replace(/1$/, '2')), node(ip.replace(/1$/, '3'))]

    const result = applySubnetClustering(nodes, [], new Set())

    expect(result.nodes).toHaveLength(3)
  })

  it('returns nodes untouched when there is nothing to cluster', () => {
    const nodes = [node('8.8.8.8')]

    const result = applySubnetClustering(nodes, [], new Set())

    expect(ids(result.nodes)).toEqual(['8.8.8.8'])
  })
})
