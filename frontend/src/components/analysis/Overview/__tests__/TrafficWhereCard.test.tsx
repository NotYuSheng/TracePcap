import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

import type { ClusterGraphResponse, ClusterNode } from '@/features/cluster/services/clusterApi'
import { TrafficWhereCard } from '../TrafficWhereCard'

// The host card loads the network graph; the drawer only needs to open it, not render it.
vi.mock('@components/common/EntityDetailModal/HostDetailModal', () => ({ HostDetailModal: () => null }))

function group(id: string, label: string, bytes: number, ips: Record<string, number>): ClusterNode {
  return {
    id, label, groupType: 'asn', hostCount: Object.keys(ips).length, totalBytes: bytes, totalPackets: 1,
    conversationCount: 3, riskCount: 0, dominantProtocols: ['TCP'], sampleIps: Object.keys(ips),
    topRiskTypes: [], ipBytes: ips, ipConversations: {}, ipRisks: {},
  } as unknown as ClusterNode
}

const byOrg: ClusterGraphResponse = {
  groupType: 'asn',
  hiddenClusters: 0,
  clusters: [
    group('cluster:internal', 'Internal Network', 5000, { '192.168.7.26': 3000, '192.168.7.12': 2000 }),
    group('asn:AS3320', 'Deutsche Telekom AG (AS3320)', 3000, { '84.146.135.221': 3000 }),
  ],
  edges: [{ sourceId: 'cluster:internal', targetId: 'asn:AS3320', totalBytes: 1500, conversationCount: 4, dominantProtocol: 'RTP' }],
}

describe('TrafficWhereCard', () => {
  it('draws a tile per organisation, named without its AS number', () => {
    render(<TrafficWhereCard fileId="f" byOrg={byOrg} />)
    expect(screen.getByRole('button', { name: /^Internal Network:/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^Deutsche Telekom AG:/ })).toBeInTheDocument()
  })

  it('opens a group: its hosts, busiest first, and the groups it talks to', () => {
    render(<TrafficWhereCard fileId="f" byOrg={byOrg} />)
    fireEvent.click(screen.getByRole('button', { name: /^Internal Network:/ }))
    const ips = screen.getAllByRole('button', { name: /^192\.168\.7\./ }).map(b => b.textContent)
    expect(ips).toEqual(['192.168.7.26', '192.168.7.12'])
    expect(screen.getByText('Talks to')).toBeInTheDocument()
    expect(screen.getAllByText('Deutsche Telekom AG').length).toBeGreaterThan(0)
  })

  it('opens a group from the keyboard too', () => {
    render(<TrafficWhereCard fileId="f" byOrg={byOrg} />)
    fireEvent.keyDown(screen.getByRole('button', { name: /^Deutsche Telekom AG:/ }), { key: 'Enter' })
    expect(screen.getByRole('button', { name: '84.146.135.221' })).toBeInTheDocument()
  })
})
